"""Steam 创意工坊下载：解析物品/合集 ID，走 Steam Web API 与 steamcmd 取回 VPK。

下载完成后由调用方交给现有的服务器版流水线，本模块只负责"把 .vpk 拿到本地"。
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any, Mapping, Optional
from urllib.parse import parse_qs, urlsplit

import httpx

logger = logging.getLogger("vpk_uploader.steam_workshop")

STEAM_API_BASE = "https://api.steampowered.com"
DEFAULT_APPID = 550  # Left 4 Dead 2
WORKSHOP_ID_RE = re.compile(r"^[0-9]{6,20}$")
WORKSHOP_URL_HOSTS = {"steamcommunity.com", "www.steamcommunity.com"}
# Steam Web API 给出的 file_url 只允许落在 Valve 自己的下载域上，避免被接口数据牵着去访问任意主机。
DIRECT_DOWNLOAD_HOST_SUFFIXES = (
    ".steamusercontent.com",
    ".steamcontent.com",
    ".steamstatic.com",
    ".akamaihd.net",
)
VPK_MAGIC = b"\x34\x12\xaa\x55"
COLLECTION_FILETYPE = 2
MAX_COLLECTION_DEPTH = 3
MAX_ITEMS_PER_JOB = 200
TRUE_VALUES = {"1", "true", "yes", "on"}


class WorkshopError(Exception):
    """创意工坊处理失败，message 直接展示给调用方。"""


@dataclass(frozen=True)
class WorkshopItemDetails:
    published_file_id: str
    title: str
    file_size: int
    consumer_app_id: Optional[int]
    filename: str
    file_url: str
    banned: bool
    ban_reason: str
    preview_url: str = ""

    @property
    def display_title(self) -> str:
        return self.title or f"workshop_{self.published_file_id}"

    @property
    def has_legacy_vpk(self) -> bool:
        """只有老式 UGC 才有可直接下载的 file_url。

        物品内容托管在 SteamPipe 上时这个字段会退化成预览图地址（此时 filename 是图片名，
        file_size 也是图片大小），照着下会拿到一张 PNG。这种物品只能交给 steamcmd。
        """
        if not self.file_url or self.file_url == self.preview_url:
            return False
        return self.filename.lower().endswith(".vpk")


def _env_bool(env: Mapping[str, str], key: str, default: bool) -> bool:
    raw = str(env.get(key, "")).strip().lower()
    if raw == "":
        return default
    return raw in TRUE_VALUES


def _env_int(env: Mapping[str, str], key: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(str(env.get(key, default)).strip())
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


@dataclass(frozen=True)
class WorkshopConfig:
    appid: int = DEFAULT_APPID
    steamcmd_home: str = "/app/data/steamcmd"
    steamcmd_dist: str = "/opt/steamcmd-dist"
    download_timeout_seconds: int = 1800
    api_timeout_seconds: int = 20
    retries: int = 3
    max_queued_jobs: int = 32
    direct_download_enabled: bool = True
    enforce_appid: bool = True
    job_retention_hours: int = 72

    @property
    def steamcmd_script(self) -> str:
        return os.path.join(self.steamcmd_home, "steamcmd.sh")

    def steamcmd_available(self) -> bool:
        return os.path.isfile(self.steamcmd_script) or os.path.isdir(self.steamcmd_dist)

    def public_status(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "appid": self.appid,
            "steamcmd_available": self.steamcmd_available(),
            "steamcmd_installed": os.path.isfile(self.steamcmd_script),
            "direct_download_enabled": self.direct_download_enabled,
            "accepts_supplied_details": True,
            "max_queued_jobs": self.max_queued_jobs,
        }


def load_workshop_config(env: Optional[Mapping[str, str]] = None) -> WorkshopConfig:
    env = os.environ if env is None else env
    data_dir = env.get("DATA_DIR") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data"
    )
    return WorkshopConfig(
        appid=_env_int(env, "STEAM_WORKSHOP_APPID", DEFAULT_APPID, 1, 2_000_000_000),
        steamcmd_home=env.get("STEAMCMD_HOME") or os.path.join(data_dir, "steamcmd"),
        steamcmd_dist=env.get("STEAMCMD_DIST") or "/opt/steamcmd-dist",
        download_timeout_seconds=_env_int(env, "STEAM_WORKSHOP_TIMEOUT_SECONDS", 1800, 60, 21600),
        api_timeout_seconds=_env_int(env, "STEAM_WORKSHOP_API_TIMEOUT_SECONDS", 20, 5, 120),
        retries=_env_int(env, "STEAM_WORKSHOP_RETRIES", 3, 1, 6),
        max_queued_jobs=_env_int(env, "STEAM_WORKSHOP_MAX_QUEUED_JOBS", 32, 1, 500),
        direct_download_enabled=_env_bool(env, "STEAM_WORKSHOP_DIRECT_DOWNLOAD", True),
        enforce_appid=_env_bool(env, "STEAM_WORKSHOP_ENFORCE_APPID", True),
        job_retention_hours=_env_int(env, "STEAM_WORKSHOP_JOB_RETENTION_HOURS", 72, 1, 24 * 30),
    )


def parse_workshop_id(raw: str) -> str:
    """接受纯数字 ID，或 steamcommunity 的 filedetails 链接。"""
    value = (raw or "").strip()
    if not value:
        raise WorkshopError("创意工坊 ID 为空")
    if WORKSHOP_ID_RE.match(value):
        return value

    if "://" not in value:
        value = f"https://{value}"
    parsed = urlsplit(value)
    host = (parsed.hostname or "").lower()
    if host not in WORKSHOP_URL_HOSTS:
        raise WorkshopError(f"无法识别的创意工坊地址：{raw.strip()[:120]}")

    candidate = ""
    query_ids = parse_qs(parsed.query).get("id") or []
    if query_ids:
        candidate = query_ids[0].strip()
    if not candidate:
        # 兼容 /sharedfiles/filedetails/123456 这种没有查询参数的写法。
        tail = [part for part in parsed.path.split("/") if part]
        if tail:
            candidate = tail[-1].strip()
    if not WORKSHOP_ID_RE.match(candidate):
        raise WorkshopError(f"链接中没有找到创意工坊 ID：{raw.strip()[:120]}")
    return candidate


def parse_workshop_ids(raw: Any) -> list[str]:
    """把一行一个的文本、或字符串列表解析成去重后的 ID 列表（保持原顺序）。"""
    if raw is None:
        return []
    if isinstance(raw, str):
        entries = re.split(r"[\r\n,;\s]+", raw)
    elif isinstance(raw, (list, tuple)):
        entries = []
        for item in raw:
            entries.extend(re.split(r"[\r\n,;\s]+", str(item)))
    else:
        raise WorkshopError("创意工坊 ID 列表格式不正确")

    seen: set[str] = set()
    result: list[str] = []
    for entry in entries:
        if not entry.strip():
            continue
        workshop_id = parse_workshop_id(entry)
        if workshop_id in seen:
            continue
        seen.add(workshop_id)
        result.append(workshop_id)
        if len(result) > MAX_ITEMS_PER_JOB:
            raise WorkshopError(f"单次最多处理 {MAX_ITEMS_PER_JOB} 个创意工坊物品")
    return result


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def direct_download_host_allowed(url: str) -> bool:
    parsed = urlsplit(url or "")
    if parsed.scheme not in {"http", "https"}:
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    return any(host == suffix.lstrip(".") or host.endswith(suffix) for suffix in DIRECT_DOWNLOAD_HOST_SUFFIXES)


def details_from_payload(
    workshop_id: str, payload: Any, appid: int
) -> Optional[WorkshopItemDetails]:
    """用调用方已经查好的 Steam 元数据构造 details，省掉节点自己访问 Web API。

    节点所在机房经常连不上 api.steampowered.com（实测三台里只有一台通），
    但 UGC CDN 是通的。让 NewAnneWeb 把直链带过来，节点就只需要下载。

    直链依旧要过 DIRECT_DOWNLOAD_HOST_SUFFIXES 白名单，调用方塞不进任意主机；
    appid 对不上也直接拒绝。任何一项不合格都返回 None，由调用处回退到 Web API。
    """
    if not isinstance(payload, Mapping):
        return None

    file_url = str(payload.get("file_url") or "").strip()
    if not file_url or not direct_download_host_allowed(file_url):
        return None
    # 调用方给的地址一律要求 https：明文 http 下载会被链路上的人换掉内容。
    if urlsplit(file_url).scheme != "https":
        return None

    filename = str(payload.get("filename") or "").strip()
    if not filename.lower().endswith(".vpk"):
        return None

    supplied_appid = _as_int(payload.get("consumer_app_id") or payload.get("app_id"), 0) or None
    if supplied_appid is not None and supplied_appid != appid:
        return None

    return WorkshopItemDetails(
        published_file_id=str(workshop_id),
        title=str(payload.get("title") or "").strip(),
        file_size=max(0, _as_int(payload.get("file_size"), 0)),
        consumer_app_id=supplied_appid,
        filename=filename,
        file_url=file_url,
        banned=False,
        ban_reason="",
        preview_url="",
    )


def parse_supplied_details(raw: Any) -> dict[str, dict[str, Any]]:
    """把请求里的 details 映射规整成 {工坊 ID: 原始字典}；无法识别的键直接丢掉。"""
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise WorkshopError("details 必须是以创意工坊 ID 为键的对象")

    result: dict[str, dict[str, Any]] = {}
    for key, value in raw.items():
        if not isinstance(value, Mapping):
            continue
        try:
            workshop_id = parse_workshop_id(str(key))
        except WorkshopError:
            continue
        result[workshop_id] = dict(value)
    return result


class SteamWebApiClient:
    """ISteamRemoteStorage 的两个公开接口，不需要 API Key。"""

    def __init__(self, config: WorkshopConfig, client_factory=None):
        self.config = config
        self._client_factory = client_factory or (
            lambda: httpx.Client(timeout=config.api_timeout_seconds, follow_redirects=True)
        )

    def _post(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        try:
            with self._client_factory() as client:
                response = client.post(f"{STEAM_API_BASE}{path}", data=data)
                response.raise_for_status()
                payload = response.json()
        except httpx.HTTPError as exc:
            raise WorkshopError(f"访问 Steam Web API 失败：{exc}") from exc
        except ValueError as exc:
            raise WorkshopError("Steam Web API 返回了无法解析的内容") from exc
        if not isinstance(payload, dict):
            raise WorkshopError("Steam Web API 返回了无法解析的内容")
        response_body = payload.get("response")
        return response_body if isinstance(response_body, dict) else {}

    def get_details(self, published_file_ids: list[str]) -> dict[str, WorkshopItemDetails]:
        if not published_file_ids:
            return {}
        data: dict[str, Any] = {"itemcount": len(published_file_ids)}
        for index, item_id in enumerate(published_file_ids):
            data[f"publishedfileids[{index}]"] = item_id
        body = self._post("/ISteamRemoteStorage/GetPublishedFileDetails/v1/", data)

        results: dict[str, WorkshopItemDetails] = {}
        for entry in body.get("publishedfiledetails") or []:
            if not isinstance(entry, dict):
                continue
            item_id = str(entry.get("publishedfileid") or "").strip()
            if not item_id or _as_int(entry.get("result"), 0) != 1:
                continue
            results[item_id] = WorkshopItemDetails(
                published_file_id=item_id,
                title=str(entry.get("title") or "").strip(),
                file_size=_as_int(entry.get("file_size"), 0),
                consumer_app_id=_as_int(entry.get("consumer_app_id"), 0) or None,
                filename=str(entry.get("filename") or "").strip(),
                file_url=str(entry.get("file_url") or "").strip(),
                banned=bool(entry.get("banned")),
                ban_reason=str(entry.get("ban_reason") or "").strip(),
                preview_url=str(entry.get("preview_url") or "").strip(),
            )
        return results

    def expand_collection(self, collection_id: str, depth: int = 0) -> list[str]:
        """展开合集，返回成员物品 ID；传入的不是合集时返回空列表。"""
        if depth >= MAX_COLLECTION_DEPTH:
            return []
        body = self._post(
            "/ISteamRemoteStorage/GetCollectionDetails/v1/",
            {"collectioncount": 1, "publishedfileids[0]": collection_id},
        )
        members: list[str] = []
        for entry in body.get("collectiondetails") or []:
            if not isinstance(entry, dict) or _as_int(entry.get("result"), 0) != 1:
                continue
            for child in entry.get("children") or []:
                if not isinstance(child, dict):
                    continue
                child_id = str(child.get("publishedfileid") or "").strip()
                if not WORKSHOP_ID_RE.match(child_id):
                    continue
                if _as_int(child.get("filetype"), 0) == COLLECTION_FILETYPE:
                    members.extend(self.expand_collection(child_id, depth + 1))
                else:
                    members.append(child_id)

        seen: set[str] = set()
        ordered: list[str] = []
        for member in members:
            if member in seen:
                continue
            seen.add(member)
            ordered.append(member)
        return ordered


class SteamCmdRunner:
    """把镜像内置的 steamcmd 复制到持久化目录后调用，保留自更新与下载缓存。"""

    def __init__(self, config: WorkshopConfig):
        self.config = config
        self._lock = threading.Lock()

    @property
    def available(self) -> bool:
        return self.config.steamcmd_available()

    def ensure_installed(self) -> str:
        script = self.config.steamcmd_script
        if os.path.isfile(script):
            return script
        dist = self.config.steamcmd_dist
        if not os.path.isdir(dist):
            raise WorkshopError(
                "当前镜像没有内置 steamcmd。steamcmd 只提供 32 位 x86 版本，"
                "linux/arm64 镜像无法安装；请在 amd64 主机上运行本节点。"
            )
        os.makedirs(self.config.steamcmd_home, exist_ok=True)
        shutil.copytree(dist, self.config.steamcmd_home, dirs_exist_ok=True)
        os.chmod(script, 0o755)
        logger.info("steamcmd installed into %s", self.config.steamcmd_home)
        return script

    def content_dir(self, published_file_id: str) -> Optional[str]:
        roots = (
            self.config.steamcmd_home,
            os.path.join(self.config.steamcmd_home, "Steam"),
        )
        for root in roots:
            candidate = os.path.join(
                root, "steamapps", "workshop", "content", str(self.config.appid), published_file_id
            )
            if os.path.isdir(candidate):
                return candidate
        return None

    def _build_command(self, script: str, published_file_id: str) -> list[str]:
        return [
            script,
            "+@ShutdownOnFailedCommand", "1",
            "+@NoPromptForPassword", "1",
            "+login", "anonymous",
            "+workshop_download_item", str(self.config.appid), published_file_id,
            "+quit",
        ]

    def download(self, published_file_id: str, log=None) -> str:
        """下载一个创意工坊物品，返回内容目录。失败抛 WorkshopError。"""
        script = self.ensure_installed()
        env = {**os.environ, "HOME": self.config.steamcmd_home}
        last_error = "steamcmd 未返回具体错误"

        with self._lock:  # steamcmd 对同一个安装目录不支持并发调用
            for attempt in range(1, self.config.retries + 1):
                # 重跑之前先清掉半截内容，避免把不完整的目录当成成功结果。
                stale = self.content_dir(published_file_id)
                if stale and attempt > 1:
                    shutil.rmtree(stale, ignore_errors=True)
                try:
                    completed = subprocess.run(
                        self._build_command(script, published_file_id),
                        cwd=self.config.steamcmd_home,
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        timeout=self.config.download_timeout_seconds,
                        check=False,
                    )
                except subprocess.TimeoutExpired:
                    last_error = f"steamcmd 下载超时（超过 {self.config.download_timeout_seconds} 秒）"
                except OSError as exc:
                    raise WorkshopError(f"无法启动 steamcmd：{exc}") from exc
                else:
                    output = completed.stdout.decode("utf-8", "replace")
                    if log is not None:
                        log(output[-2000:])
                    content = self.content_dir(published_file_id)
                    if content and os.listdir(content):
                        return content
                    last_error = self._failure_reason(output, completed.returncode)

                logger.warning(
                    "steamcmd download failed item=%s attempt=%s/%s error=%s",
                    published_file_id, attempt, self.config.retries, last_error,
                )
                if attempt < self.config.retries:
                    time.sleep(min(15, 5 * attempt))

        raise WorkshopError(f"steamcmd 下载失败：{last_error}")

    def cleanup(self, published_file_id: str) -> None:
        content = self.content_dir(published_file_id)
        if content:
            shutil.rmtree(content, ignore_errors=True)

    def _failure_reason(self, output: str, return_code: int) -> str:
        """steamcmd 自更新失败时不往 stdout 写东西，真正的原因只在它自己的日志里。"""
        reason = _steamcmd_error(output, return_code)
        if not reason.startswith("steamcmd 退出码"):
            return reason
        log_path = os.path.join(self.config.steamcmd_home, "Steam", "logs", "bootstrap_log.txt")
        try:
            with open(log_path, encoding="utf-8", errors="replace") as handle:
                lines = [line.strip() for line in handle.readlines()[-40:] if line.strip()]
        except OSError:
            return reason
        for line in reversed(lines):
            if "failed" in line.lower() or "error" in line.lower():
                return f"{reason}（{line[:200]}）"
        return reason


def _steamcmd_error(output: str, return_code: int) -> str:
    for line in reversed((output or "").splitlines()):
        stripped = line.strip()
        if not stripped:
            continue
        if "ERROR!" in stripped or "Failed" in stripped or "FAILED" in stripped:
            return stripped[:300]
    return f"steamcmd 退出码 {return_code}"


def download_direct(details: WorkshopItemDetails, dest_path: str, max_bytes: int, timeout_seconds: int) -> int:
    """旧版 UGC 的 file_url 可以直接 HTTPS 取回，省掉一次 steamcmd 调用。"""
    if not direct_download_host_allowed(details.file_url):
        raise WorkshopError("创意工坊直链地址不在允许的 Steam 下载域内")
    written = 0
    try:
        with httpx.Client(timeout=timeout_seconds, follow_redirects=True) as client, \
                client.stream("GET", details.file_url) as response:
            response.raise_for_status()
            with open(dest_path, "wb") as out:
                for chunk in response.iter_bytes(1024 * 1024):
                    written += len(chunk)
                    if max_bytes and written > max_bytes:
                        raise WorkshopError(f"文件过大，超过 {max_bytes // 1024 // 1024} MB 限制")
                    out.write(chunk)
    except httpx.HTTPError as exc:
        raise WorkshopError(f"创意工坊直链下载失败：{exc}") from exc
    return written


def looks_like_vpk(path: str) -> bool:
    """按 VPK 头部魔数判断，和 vpk 库的校验保持一致。"""
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == VPK_MAGIC
    except OSError:
        return False


def collect_vpk_files(content_dir: str) -> list[str]:
    """创意工坊物品目录里可能带说明文件，只取 .vpk。"""
    found: list[str] = []
    for root, _, files in os.walk(content_dir):
        for name in files:
            if name.lower().endswith(".vpk"):
                found.append(os.path.join(root, name))
    found.sort()
    return found
