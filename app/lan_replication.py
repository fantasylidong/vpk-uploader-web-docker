from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional
from urllib.parse import urlsplit, urlunsplit

import httpx


PROTOCOL_VERSION = 1
TRUE_VALUES = {"1", "true", "yes", "on"}


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


def _normalize_peer_url(raw_url: str) -> str:
    value = raw_url.strip()
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("节点地址必须是完整的 HTTP/HTTPS URL")
    if parsed.username or parsed.password:
        raise ValueError("节点地址不能包含用户名或密码")
    if parsed.query or parsed.fragment:
        raise ValueError("节点地址不能包含查询参数或片段")

    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


@dataclass(frozen=True)
class LanPeer:
    node_id: str
    name: str
    url: str


@dataclass(frozen=True)
class LanReplicationConfig:
    node_id: str
    group: str
    token: str
    allowed_cidrs: str
    peers: tuple[LanPeer, ...] = ()
    configured_enabled: bool = True
    allow_public_peers: bool = False
    verify_tls: bool = True
    connect_timeout_seconds: int = 4
    transfer_timeout_seconds: int = 1800
    reservation_ttl_seconds: int = 3600
    retries: int = 1
    max_parallel_peers: int = 3
    disk_reserve_bytes: int = 1024 * 1024 * 1024
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def receiver_enabled(self) -> bool:
        return self.configured_enabled and bool(
            self.node_id
            and self.group
            and len(self.token) >= 32
            and self.allowed_cidrs
        )

    @property
    def enabled(self) -> bool:
        return self.receiver_enabled and bool(self.peers)

    def public_status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "receiver_enabled": self.receiver_enabled,
            "node_id": self.node_id,
            "group": self.group,
            "protocol_version": PROTOCOL_VERSION,
            "configured_peer_count": len(self.peers),
            "config_error_count": len(self.errors),
        }


@dataclass(frozen=True)
class ReplicationArtifact:
    upload_id: int
    original_name: str
    stored_name: str
    path: str
    size: int
    sha256: str

    def manifest_item(self) -> dict[str, Any]:
        return {
            "source_upload_id": self.upload_id,
            "original_name": self.original_name,
            "stored_name": self.stored_name,
            "size": self.size,
            "sha256": self.sha256,
        }


def _parse_peers(raw: str, local_node_id: str) -> tuple[tuple[LanPeer, ...], tuple[str, ...]]:
    raw = raw.strip()
    if not raw:
        return (), ()

    errors: list[str] = []
    parsed_items: list[Any]
    try:
        decoded = json.loads(raw)
        if not isinstance(decoded, list):
            raise ValueError("LAN_PEERS 必须是 JSON 数组")
        parsed_items = decoded
    except json.JSONDecodeError:
        parsed_items = []
        for value in raw.replace("\n", ",").split(","):
            value = value.strip()
            if not value:
                continue
            if "=" in value:
                node_id, url = value.split("=", 1)
                parsed_items.append({"id": node_id.strip(), "url": url.strip()})
            else:
                parsed_items.append({"url": value})
    except ValueError as exc:
        return (), (str(exc),)

    peers: list[LanPeer] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(parsed_items, start=1):
        if isinstance(item, str):
            item = {"url": item}
        if not isinstance(item, dict):
            errors.append(f"LAN_PEERS 第 {index} 项不是对象或 URL")
            continue

        node_id = str(item.get("id", item.get("node_id", ""))).strip()
        name = str(item.get("name", node_id)).strip() or node_id
        raw_url = str(item.get("url", "")).strip()
        if not node_id:
            errors.append(f"LAN_PEERS 第 {index} 项缺少 id")
            continue
        if node_id == local_node_id:
            continue
        if node_id in seen_ids:
            errors.append(f"LAN_PEERS 节点 ID 重复：{node_id}")
            continue
        try:
            url = _normalize_peer_url(raw_url)
        except ValueError as exc:
            errors.append(f"LAN_PEERS 节点 {node_id}：{exc}")
            continue
        seen_ids.add(node_id)
        peers.append(LanPeer(node_id=node_id, name=name or node_id, url=url))

    return tuple(peers), tuple(errors)


def load_lan_replication_config(env: Optional[Mapping[str, str]] = None) -> LanReplicationConfig:
    env = os.environ if env is None else env
    node_id = str(env.get("LAN_NODE_ID", "")).strip()
    group = str(env.get("LAN_GROUP", "")).strip()
    token = str(env.get("LAN_PEER_API_TOKEN", "")).strip()
    peers, errors = _parse_peers(str(env.get("LAN_PEERS", "")), node_id)
    errors = list(errors)
    has_lan_config = bool(node_id or group or token or peers or str(env.get("LAN_PEER_ALLOWED_CIDRS", "")).strip())
    if has_lan_config:
        if not node_id:
            errors.append("缺少 LAN_NODE_ID")
        if not group:
            errors.append("缺少 LAN_GROUP")
        if len(token) < 32:
            errors.append("LAN_PEER_API_TOKEN 至少需要 32 个字符")
        if not str(env.get("LAN_PEER_ALLOWED_CIDRS", "")).strip():
            errors.append("缺少 LAN_PEER_ALLOWED_CIDRS")
    disk_reserve_mb = _env_int(env, "LAN_DISK_RESERVE_MB", 1024, 0, 1024 * 1024)

    return LanReplicationConfig(
        node_id=node_id,
        group=group,
        token=token,
        allowed_cidrs=str(env.get("LAN_PEER_ALLOWED_CIDRS", "")).strip(),
        peers=peers,
        configured_enabled=_env_bool(env, "LAN_REPLICATION_ENABLED", True),
        allow_public_peers=_env_bool(env, "LAN_ALLOW_PUBLIC_PEERS", False),
        verify_tls=_env_bool(env, "LAN_PEER_TLS_VERIFY", True),
        connect_timeout_seconds=_env_int(env, "LAN_PEER_CONNECT_TIMEOUT_SECONDS", 4, 1, 60),
        transfer_timeout_seconds=_env_int(env, "LAN_PEER_TRANSFER_TIMEOUT_SECONDS", 1800, 30, 7200),
        reservation_ttl_seconds=_env_int(env, "LAN_RESERVATION_TTL_SECONDS", 3600, 300, 7200),
        retries=_env_int(env, "LAN_REPLICATION_RETRIES", 1, 0, 5),
        max_parallel_peers=_env_int(env, "LAN_MAX_PARALLEL_PEERS", 3, 1, 16),
        disk_reserve_bytes=disk_reserve_mb * 1024 * 1024,
        errors=tuple(errors),
    )


def _address_is_private(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    return parsed.is_private or parsed.is_loopback or parsed.is_link_local


def peer_host_is_private(peer: LanPeer) -> bool:
    host = urlsplit(peer.url).hostname or ""
    if _address_is_private(host):
        return True
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            if item and len(item) >= 5 and item[4]
        }
    except OSError:
        return False
    return bool(addresses) and all(_address_is_private(address) for address in addresses)


def _auth_headers(config: LanReplicationConfig) -> dict[str, str]:
    return {
        "Accept": "application/json",
        "Authorization": f"Bearer {config.token}",
        "X-LAN-Group": config.group,
        "X-LAN-Node": config.node_id,
        "User-Agent": "VPK-Uploader-LAN/1.0",
    }


def _response_detail(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        detail = str(payload.get("detail", "")).strip()
        if detail:
            return detail[:500]
    return f"HTTP {response.status_code}"


async def _replicate_to_peer(
    config: LanReplicationConfig,
    peer: LanPeer,
    artifacts: tuple[ReplicationArtifact, ...],
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "node_id": peer.node_id,
        "name": peer.name,
        "status": "failed",
        "uploaded": [],
        "already_present": [],
    }
    if not config.allow_public_peers and not await asyncio.to_thread(peer_host_is_private, peer):
        result.update(status="rejected_address", detail="节点地址没有解析到私网地址")
        return result

    timeout = httpx.Timeout(
        connect=float(config.connect_timeout_seconds),
        read=float(config.transfer_timeout_seconds),
        write=float(config.transfer_timeout_seconds),
        pool=float(config.connect_timeout_seconds),
    )
    reservation_id = ""
    headers = _auth_headers(config)
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            verify=config.verify_tls,
            follow_redirects=False,
            transport=transport,
        ) as client:
            capability_response = await client.get(
                f"{peer.url}/api/lan/replication/capabilities",
                headers=headers,
            )
            if capability_response.status_code != 200:
                result.update(status="offline", detail=_response_detail(capability_response))
                return result
            capability = capability_response.json()
            if not isinstance(capability, dict):
                result.update(status="invalid_response", detail="节点能力响应不是 JSON 对象")
                return result
            if str(capability.get("lan_group", "")) != config.group:
                result.update(status="group_mismatch", detail="节点返回的内网组不一致")
                return result
            if str(capability.get("node_id", "")) != peer.node_id:
                result.update(status="identity_mismatch", detail="节点返回的 ID 与配置不一致")
                return result
            if int(capability.get("protocol_version", 0)) != PROTOCOL_VERSION:
                result.update(status="protocol_mismatch", detail="节点复制协议版本不兼容")
                return result

            preflight_response = await client.post(
                f"{peer.url}/api/lan/replication/preflight",
                headers=headers,
                json={
                    "source_node_id": config.node_id,
                    "lan_group": config.group,
                    "reservation_ttl_seconds": config.reservation_ttl_seconds,
                    "artifacts": [artifact.manifest_item() for artifact in artifacts],
                },
            )
            if preflight_response.status_code != 200:
                result.update(status="preflight_failed", detail=_response_detail(preflight_response))
                return result
            preflight = preflight_response.json()
            if not isinstance(preflight, dict):
                result.update(status="invalid_response", detail="节点预检响应不是 JSON 对象")
                return result

            result["storage"] = preflight.get("storage", {})
            result["already_present"] = preflight.get("already_present", [])
            preflight_status = str(preflight.get("status", ""))
            if preflight_status == "already_present":
                result["status"] = "already_present"
                return result
            if preflight_status == "insufficient_capacity":
                result.update(
                    status="skipped_capacity",
                    detail=str(preflight.get("detail", "目标节点容量不足")),
                    required_bytes=int(preflight.get("required_bytes", 0)),
                )
                return result
            if preflight_status != "reserved":
                result.update(status="preflight_failed", detail="节点没有返回有效的容量预留")
                return result

            reservation_id = str(preflight.get("reservation_id", ""))
            accepted_hashes = {
                str(item.get("sha256", ""))
                for item in preflight.get("accepted", [])
                if isinstance(item, dict)
            }
            if not reservation_id or not accepted_hashes:
                result.update(status="preflight_failed", detail="节点容量预留内容为空")
                return result

            for artifact in artifacts:
                if artifact.sha256 not in accepted_hashes:
                    continue
                last_detail = ""
                uploaded_payload: Optional[dict[str, Any]] = None
                for _attempt in range(config.retries + 1):
                    try:
                        with open(artifact.path, "rb") as file_handle:
                            upload_response = await client.post(
                                f"{peer.url}/api/lan/replication/uploads",
                                headers=headers,
                                data={
                                    "reservation_id": reservation_id,
                                    "source_node_id": config.node_id,
                                    "source_upload_id": str(artifact.upload_id),
                                    "original_name": artifact.original_name,
                                    "sha256": artifact.sha256,
                                    "size": str(artifact.size),
                                },
                                files={
                                    "file": (
                                        artifact.stored_name,
                                        file_handle,
                                        "application/octet-stream",
                                    )
                                },
                            )
                        if upload_response.status_code == 200:
                            payload = upload_response.json()
                            if isinstance(payload, dict):
                                uploaded_payload = payload
                                break
                        last_detail = _response_detail(upload_response)
                    except (OSError, httpx.HTTPError) as exc:
                        last_detail = str(exc)[:500]

                if uploaded_payload is None:
                    result.update(
                        status="partial",
                        detail=f"{artifact.original_name} 复制失败：{last_detail or '请求失败'}",
                    )
                    return result
                if str(uploaded_payload.get("status", "")) == "already_present":
                    result["already_present"].append(uploaded_payload.get("upload", {}))
                else:
                    result["uploaded"].append(uploaded_payload.get("upload", {}))

            result["status"] = "completed"
            return result
    except (httpx.HTTPError, OSError, ValueError, TypeError) as exc:
        result.update(status="offline", detail=str(exc)[:500])
        return result
    finally:
        if reservation_id:
            try:
                async with httpx.AsyncClient(
                    timeout=timeout,
                    verify=config.verify_tls,
                    follow_redirects=False,
                    transport=transport,
                ) as client:
                    await client.post(
                        f"{peer.url}/api/lan/replication/reservations/{reservation_id}/complete",
                        headers=headers,
                    )
            except (httpx.HTTPError, OSError):
                pass


async def replicate_artifacts(
    config: LanReplicationConfig,
    artifacts: Iterable[ReplicationArtifact],
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> dict[str, Any]:
    artifact_tuple = tuple(artifacts)
    if not artifact_tuple:
        return {
            **config.public_status(),
            "complete": True,
            "completed_peer_count": 0,
            "skipped_peer_count": 0,
            "failed_peer_count": 0,
            "peers": [],
        }
    if not config.enabled:
        peer_results = [{
            "node_id": peer.node_id,
            "name": peer.name,
            "status": "configuration_error",
            "detail": "当前节点的内网复制配置不完整",
            "uploaded": [],
            "already_present": [],
        } for peer in config.peers]
        return {
            **config.public_status(),
            "complete": not config.peers and not config.errors,
            "completed_peer_count": 0,
            "skipped_peer_count": 0,
            "failed_peer_count": len(peer_results),
            "config_errors": list(config.errors),
            "peers": peer_results,
        }

    semaphore = asyncio.Semaphore(config.max_parallel_peers)

    async def run(peer: LanPeer) -> dict[str, Any]:
        async with semaphore:
            return await _replicate_to_peer(config, peer, artifact_tuple, transport=transport)

    peer_results = list(await asyncio.gather(*(run(peer) for peer in config.peers)))
    completed_statuses = {"completed", "already_present"}
    skipped_statuses = {"skipped_capacity"}
    completed_count = sum(item.get("status") in completed_statuses for item in peer_results)
    skipped_count = sum(item.get("status") in skipped_statuses for item in peer_results)
    failed_count = len(peer_results) - completed_count - skipped_count
    return {
        **config.public_status(),
        "complete": completed_count == len(peer_results) and not config.errors,
        "completed_peer_count": completed_count,
        "skipped_peer_count": skipped_count,
        "failed_peer_count": failed_count,
        "config_errors": list(config.errors),
        "peers": peer_results,
    }
