"""Steam 创意工坊下载：解析物品/合集 ID，走 Steam Web API 与 steamcmd 取回 VPK。

下载完成后由调用方交给现有的服务器版流水线，本模块只负责"把 .vpk 拿到本地"。
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any, Mapping, Optional
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlsplit, urlunsplit

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
# 同一份 UGC 文件在这些域名上路径相同。国内节点连 cdn.steamusercontent.com 单连接常被限到几百 KB/s，
# Akamai 这个老域名实测快好几倍，所以分段下载时两边一起用。
DEFAULT_DIRECT_MIRRORS = ("steamusercontent-a.akamaihd.net",)
DIRECT_PIECE_BYTES = 16 * 1024 * 1024
# steamcmd 每次启动都先找这个域名自更新，连不上就静默退出。
STEAMCMD_UPDATE_HOST = "client-download.steampowered.com"
STEAMCMD_PROBE_PORTS = (443, 80)


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
    steamcmd_update_host: str = STEAMCMD_UPDATE_HOST
    steamcmd_probe_ttl_seconds: int = 600
    steamcmd_probe_timeout_seconds: int = 5
    direct_download_attempts: int = 8
    direct_download_connections: int = 4
    direct_download_mirrors: tuple[str, ...] = DEFAULT_DIRECT_MIRRORS

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
        steamcmd_update_host=(env.get("STEAMCMD_UPDATE_HOST") or STEAMCMD_UPDATE_HOST).strip(),
        steamcmd_probe_ttl_seconds=_env_int(env, "STEAMCMD_PROBE_TTL_SECONDS", 600, 30, 86400),
        steamcmd_probe_timeout_seconds=_env_int(env, "STEAMCMD_PROBE_TIMEOUT_SECONDS", 5, 1, 30),
        direct_download_attempts=_env_int(env, "STEAM_WORKSHOP_DIRECT_ATTEMPTS", 8, 1, 30),
        direct_download_connections=_env_int(env, "STEAM_WORKSHOP_DIRECT_CONNECTIONS", 4, 1, 16),
        direct_download_mirrors=tuple(
            host.strip().lower()
            for host in str(env.get("STEAM_WORKSHOP_DIRECT_MIRRORS", ",".join(DEFAULT_DIRECT_MIRRORS))).split(",")
            if host.strip()
        ),
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


def probe_tcp_host(host: str, ports: tuple[int, ...], timeout: float) -> tuple[bool, str]:
    """能解析并连上任意一个端口就算通。steamcmd 自更新失败时什么都不输出，只能先这样探。"""
    try:
        socket.getaddrinfo(host, None)
    except OSError as exc:
        return False, f"无法解析 {host}（{exc}）"
    last_error = ""
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True, ""
        except OSError as exc:
            last_error = str(exc)
    return False, f"连不上 {host}（{last_error or '超时'}）"


class SteamCmdRunner:
    """把镜像内置的 steamcmd 复制到持久化目录后调用，保留自更新与下载缓存。"""

    def __init__(self, config: WorkshopConfig, prober=None):
        self.config = config
        self._lock = threading.Lock()
        self._prober = prober or probe_tcp_host
        self._probe_lock = threading.Lock()
        # (时间戳, 是否可用, 原因)；None 表示还没探测过。
        self._readiness: Optional[tuple[float, bool, str]] = None

    @property
    def available(self) -> bool:
        return self.config.steamcmd_available()

    def _fresh_readiness(self) -> Optional[tuple[bool, str]]:
        cached = self._readiness
        if cached is not None and time.monotonic() - cached[0] < self.config.steamcmd_probe_ttl_seconds:
            return cached[1], cached[2]
        return None

    def _probe(self, wait: bool = False) -> tuple[bool, str]:
        if not self._probe_lock.acquire(blocking=wait):
            cached = self._readiness
            return (cached[1], cached[2]) if cached else (False, "正在检测 steamcmd 更新服务器")
        try:
            # 等锁期间别的线程可能刚探测完，直接用它的结论。
            fresh = self._fresh_readiness() if wait else None
            if fresh is not None:
                return fresh
            ok, reason = self._prober(
                self.config.steamcmd_update_host,
                STEAMCMD_PROBE_PORTS,
                self.config.steamcmd_probe_timeout_seconds,
            )
            self._readiness = (time.monotonic(), ok, reason)
            if not ok:
                logger.warning("steamcmd update host unreachable: %s", reason)
            return ok, reason
        finally:
            self._probe_lock.release()

    def readiness(self, block: bool = False) -> tuple[bool, str]:
        """steamcmd 现在能不能真的用：镜像里有它还不够，还得连得上自更新服务器。

        block=False 时不在调用线程里做网络探测：结果过期就在后台刷新，先返回上一次的结论，
        从没探测过则当作不可用 —— 宁可让上游暂时拒掉，也别让玩家排一个必败的任务。
        """
        if not self.available:
            return False, "当前镜像没有内置 steamcmd（只支持 amd64）"
        fresh = self._fresh_readiness()
        if fresh is not None:
            return fresh
        if block:
            return self._probe(wait=True)
        self.refresh_readiness_async()
        cached = self._readiness
        if cached is not None:
            return cached[1], cached[2]
        return False, "正在检测 steamcmd 更新服务器"

    def refresh_readiness_async(self) -> None:
        if not self.available or self._probe_lock.locked():
            return
        threading.Thread(target=self._probe, name="steamcmd-probe", daemon=True).start()

    def _remember(self, ok: bool, reason: str) -> None:
        self._readiness = (time.monotonic(), ok, reason)

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
        ready, reason = self.readiness(block=True)
        if not ready:
            # 连不上自更新服务器时 steamcmd 每次都会静默退出，重试三轮只是白等。
            raise WorkshopError(f"steamcmd 当前不可用：{reason}")
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
                        self._remember(True, "")
                        return content
                    last_error = self._failure_reason(output, completed.returncode)
                    if self.config.steamcmd_update_host in last_error:
                        # 自更新失败：记下来让 summary 立刻反映，并且不用再重试了。
                        self._remember(False, last_error)
                        break

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


def _format_mb(byte_count: int) -> str:
    return f"{byte_count / 1024 / 1024:.1f} MB"


class _RangeUnsupported(Exception):
    """服务器不认 Range，只能单连接从头下。"""


def direct_download_urls(file_url: str, mirrors=DEFAULT_DIRECT_MIRRORS) -> list[str]:
    """原直链加上同一路径的镜像域名（都得在 Steam 下载域白名单里）。"""
    parsed = urlsplit(file_url)
    urls = [file_url]
    if not parsed.path.startswith("/ugc/"):
        return urls
    for host in mirrors:
        host = (host or "").strip().lower()
        if not host or host == (parsed.hostname or "").lower():
            continue
        candidate = urlunsplit(("https", host, parsed.path, parsed.query, ""))
        if direct_download_host_allowed(candidate) and candidate not in urls:
            urls.append(candidate)
    return urls


def _is_permanent_http_error(status: int) -> bool:
    return 400 <= status < 500 and status not in (408, 429)


def download_direct(
    details: WorkshopItemDetails,
    dest_path: str,
    max_bytes: int,
    timeout_seconds: int,
    attempts: int = 8,
    client_factory=None,
    sleep=time.sleep,
    connections: int = 4,
    mirrors=DEFAULT_DIRECT_MIRRORS,
    piece_bytes: int = DIRECT_PIECE_BYTES,
) -> int:
    """旧版 UGC 的 file_url 可以直接 HTTPS 取回，省掉一次 steamcmd 调用。

    国内节点连 Steam CDN 单连接常被限速、下到一半还会被断开（#58-59 实测 30 分钟只下了 63 MB），
    所以知道文件大小时切成若干段，多路并行、原域名和镜像域名轮着用，每段断了就从断点接着下；
    服务器不认 Range 时退回单连接下载。总共不超过 timeout_seconds。
    """
    if not direct_download_host_allowed(details.file_url):
        raise WorkshopError("创意工坊直链地址不在允许的 Steam 下载域内")
    # file_size 只有老式 UGC 才是 VPK 的真实大小，用来分段和判断是不是下完了。
    expected = details.file_size if details.has_legacy_vpk and details.file_size > 0 else 0
    if max_bytes and expected > max_bytes:
        raise WorkshopError(f"文件过大，超过 {max_bytes // 1024 // 1024} MB 限制")
    factory = client_factory or (
        lambda: httpx.Client(timeout=httpx.Timeout(60.0, connect=15.0), follow_redirects=True)
    )
    urls = direct_download_urls(details.file_url, mirrors)
    deadline = time.monotonic() + timeout_seconds
    attempts = max(1, attempts)

    if expected and connections > 1 and expected > piece_bytes:
        try:
            return _download_segmented(
                details, urls, dest_path, expected, deadline, timeout_seconds,
                attempts, factory, sleep, connections, piece_bytes,
            )
        except _RangeUnsupported:
            logger.info("workshop direct download: range unsupported, falling back to one stream item=%s",
                        details.published_file_id)
    return _download_single(details, urls, dest_path, max_bytes, expected, deadline, timeout_seconds,
                            attempts, factory, sleep)


def _download_segmented(details, urls, dest_path, expected, deadline, timeout_seconds,
                        attempts, factory, sleep, connections, piece_bytes) -> int:
    pieces = [(start, min(start + piece_bytes, expected) - 1) for start in range(0, expected, piece_bytes)]
    lock = threading.Lock()
    stop = threading.Event()
    bad_urls: set[str] = set()
    next_piece = [0]
    received = [0]

    with open(dest_path, "wb") as out:
        out.truncate(expected)

    def pick_url(index: int, attempt: int) -> str:
        with lock:
            usable = [url for url in urls if url not in bad_urls] or list(urls)
        return usable[(index + attempt) % len(usable)]

    def fetch_piece(client, out, index: int, start: int, end: int) -> None:
        pos = start
        attempt = 0
        last_error = ""
        while pos <= end:
            if stop.is_set():
                return
            if time.monotonic() > deadline:
                raise WorkshopError(
                    f"创意工坊直链下载超时（{timeout_seconds} 秒内只下到 {_format_mb(received[0])} / {_format_mb(expected)}）"
                )
            url = pick_url(index, attempt)
            try:
                with client.stream("GET", url, headers={"Range": f"bytes={pos}-{end}"}) as response:
                    if not direct_download_host_allowed(str(response.url)):
                        raise WorkshopError("创意工坊直链被跳转到了 Steam 下载域以外的地址")
                    if response.status_code == 200:
                        raise _RangeUnsupported()
                    response.raise_for_status()
                    if not str(response.headers.get("content-range", "")).startswith(f"bytes {pos}-"):
                        raise _RangeUnsupported()
                    out.seek(pos)
                    for chunk in response.iter_bytes():
                        if stop.is_set():
                            return
                        chunk = chunk[: end - pos + 1]
                        out.write(chunk)
                        pos += len(chunk)
                        with lock:
                            received[0] += len(chunk)
                        if pos > end:
                            break
                        if time.monotonic() > deadline:
                            raise WorkshopError(
                                f"创意工坊直链下载超时（{timeout_seconds} 秒内只下到 {_format_mb(received[0])} / {_format_mb(expected)}）"
                            )
                if pos > end:
                    return
                last_error = "连接提前结束"
            except (WorkshopError, _RangeUnsupported):
                raise
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                last_error = f"{urlsplit(url).hostname} HTTP {status}"
                if _is_permanent_http_error(status):
                    # 这个域名拿不到这份文件，换别的域名；全都拿不到才算失败。
                    with lock:
                        bad_urls.add(url)
                        if len(bad_urls) >= len(urls):
                            raise WorkshopError(f"创意工坊直链下载失败：{last_error}") from exc
                    continue
            except httpx.HTTPError as exc:
                last_error = f"{urlsplit(url).hostname}: {exc or exc.__class__.__name__}"
            attempt += 1
            if attempt >= attempts:
                raise WorkshopError(
                    f"创意工坊直链下载失败（第 {index + 1}/{len(pieces)} 段试了 {attempts} 次，"
                    f"已下载 {_format_mb(received[0])} / {_format_mb(expected)}）：{last_error}"
                )
            logger.warning(
                "workshop direct piece interrupted item=%s piece=%s/%s attempt=%s/%s error=%s",
                details.published_file_id, index + 1, len(pieces), attempt, attempts, last_error,
            )
            sleep(min(10, 2 * attempt))

    def worker() -> None:
        with factory() as client, open(dest_path, "r+b") as out:
            while not stop.is_set():
                with lock:
                    index = next_piece[0]
                    if index >= len(pieces):
                        return
                    next_piece[0] += 1
                start, end = pieces[index]
                fetch_piece(client, out, index, start, end)

    workers = min(connections, len(pieces))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(worker) for _ in range(workers)]
        first_error: Optional[BaseException] = None
        for future in futures:
            try:
                future.result()
            except BaseException as exc:  # noqa: BLE001  一路失败就叫停其它路，再把第一个错误抛出去
                stop.set()
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error
    return expected


def _download_single(details, urls, dest_path, max_bytes, expected, deadline, timeout_seconds,
                     attempts, factory, sleep) -> int:
    """单连接下载，断了用 Range 接着下；服务器不认 Range 就从头来。"""
    written = 0
    last_error = ""
    bad_urls: set[str] = set()
    open(dest_path, "wb").close()

    for attempt in range(1, attempts + 1):
        usable = [url for url in urls if url not in bad_urls]
        if not usable:
            break
        url = usable[(attempt - 1) % len(usable)]
        headers = {"Range": f"bytes={written}-"} if written else {}
        try:
            with factory() as client, client.stream("GET", url, headers=headers) as response:
                if not direct_download_host_allowed(str(response.url)):
                    raise WorkshopError("创意工坊直链被跳转到了 Steam 下载域以外的地址")
                if written and response.status_code == 416 and expected and written >= expected:
                    return written
                response.raise_for_status()
                resumed = written > 0 and response.status_code == 206 and \
                    str(response.headers.get("content-range", "")).startswith(f"bytes {written}-")
                if not resumed:
                    # 服务器不认 Range（或者第一次下载）：从头来。
                    written = 0
                with open(dest_path, "ab" if resumed else "wb") as out:
                    # 不指定块大小：收到多少写多少，断线时已收到的字节都已落盘，续传位置才准。
                    for chunk in response.iter_bytes():
                        if max_bytes and written + len(chunk) > max_bytes:
                            raise WorkshopError(f"文件过大，超过 {max_bytes // 1024 // 1024} MB 限制")
                        out.write(chunk)
                        written += len(chunk)
                        if time.monotonic() > deadline:
                            raise WorkshopError(
                                f"创意工坊直链下载超时（{timeout_seconds} 秒内只下到 {_format_mb(written)}）"
                            )
            if not expected or written >= expected:
                return written
            last_error = f"连接提前结束（{_format_mb(written)} / {_format_mb(expected)}）"
        except WorkshopError:
            raise
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            last_error = f"{urlsplit(url).hostname} HTTP {status}"
            # 4xx（限流和超时除外）在这个域名上重试也没用，换别的域名。
            if _is_permanent_http_error(status):
                bad_urls.add(url)
                continue
        except httpx.HTTPError as exc:
            last_error = str(exc) or exc.__class__.__name__

        if attempt >= attempts or time.monotonic() > deadline:
            break
        logger.warning(
            "workshop direct download interrupted item=%s attempt=%s/%s received=%s error=%s",
            details.published_file_id, attempt, attempts, written, last_error,
        )
        sleep(min(10, 2 * attempt))

    progress = f"，已下载 {_format_mb(written)}" + (f" / {_format_mb(expected)}" if expected else "")
    raise WorkshopError(f"创意工坊直链下载失败（试了 {attempt} 次{progress}）：{last_error}")


def looks_like_vpk(path: str) -> bool:
    """按 VPK 头部魔数判断，和 vpk 库的校验保持一致。"""
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == VPK_MAGIC
    except OSError:
        return False


def collect_vpk_files(content_dir: str) -> list[str]:
    """取出物品目录里的 VPK。

    目录里可能带说明文件；老式 UGC 用 steamcmd 取回时文件名不一定是 .vpk（比如 *_legacy.bin），
    所以扩展名不对的再按 VPK 文件头认一遍。
    """
    found: list[str] = []
    for root, _, files in os.walk(content_dir):
        for name in files:
            path = os.path.join(root, name)
            if name.lower().endswith(".vpk") or looks_like_vpk(path):
                found.append(path)
    found.sort()
    return found


def describe_files(content_dir: str, limit: int = 5) -> str:
    """失败时告诉调用方下载到了什么，方便判断是不是物品本身就不是地图包。"""
    names: list[str] = []
    for root, _, files in os.walk(content_dir):
        for name in files:
            names.append(os.path.relpath(os.path.join(root, name), content_dir))
    names.sort()
    if not names:
        return "目录是空的"
    shown = "、".join(names[:limit])
    return shown + (f" 等 {len(names)} 个文件" if len(names) > limit else "")
