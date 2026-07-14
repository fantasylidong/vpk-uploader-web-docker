import posixpath
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional


COMMAND_MAX_LENGTH = 1000
COMMAND_OUTPUT_MAX_BYTES = 64 * 1024
COMMAND_TIMEOUT_SECONDS = 15


def _sum_network(stats: dict, key: str) -> int:
    return sum(int(item.get(key, 0)) for item in stats.get("networks", {}).values())


def _sum_block_io(stats: dict, operation: str) -> int:
    entries = stats.get("blkio_stats", {}).get("io_service_bytes_recursive") or []
    return sum(int(item.get("value", 0)) for item in entries if item.get("op", "").lower() == operation.lower())


def _cpu_percent(stats: dict) -> float:
    current = stats.get("cpu_stats", {})
    previous = stats.get("precpu_stats", {})
    cpu_delta = current.get("cpu_usage", {}).get("total_usage", 0) - previous.get("cpu_usage", {}).get("total_usage", 0)
    system_delta = current.get("system_cpu_usage", 0) - previous.get("system_cpu_usage", 0)
    cpu_count = len(current.get("cpu_usage", {}).get("percpu_usage") or []) or current.get("online_cpus", 1)
    if cpu_delta <= 0 or system_delta <= 0:
        return 0.0
    return round(cpu_delta / system_delta * cpu_count * 100, 2)


class DockerManager:
    def __init__(self, client=None):
        if client is None:
            import docker
            client = docker.from_env()
        self.client = client

    def ping(self) -> bool:
        return bool(self.client.ping())

    def list_containers(self) -> list[dict]:
        containers = self.client.containers.list(all=True)
        running = [container for container in containers if container.status == "running"]

        def read_stats(container):
            try:
                return container.id, container.stats(stream=False)
            except Exception:
                return container.id, {}

        stats_by_id = {}
        if running:
            with ThreadPoolExecutor(max_workers=min(8, len(running))) as executor:
                stats_by_id.update(executor.map(read_stats, running))

        result = []
        for container in containers:
            stats = stats_by_id.get(container.id, {})
            memory = stats.get("memory_stats", {})
            memory_usage = max(0, int(memory.get("usage", 0)) - int(memory.get("stats", {}).get("cache", 0)))
            memory_limit = int(memory.get("limit", 0))
            attrs = container.attrs
            result.append({
                "id": container.id,
                "short_id": container.id[:12],
                "name": container.name,
                "status": container.status,
                "image": (container.image.tags or [container.image.short_id])[0],
                "created": attrs.get("Created"),
                "cpu_percent": _cpu_percent(stats),
                "memory_usage": memory_usage,
                "memory_limit": memory_limit,
                "memory_percent": round(memory_usage / memory_limit * 100, 2) if memory_limit else 0,
                "network_rx": _sum_network(stats, "rx_bytes"),
                "network_tx": _sum_network(stats, "tx_bytes"),
                "block_read": _sum_block_io(stats, "Read"),
                "block_write": _sum_block_io(stats, "Write"),
                "ports": attrs.get("NetworkSettings", {}).get("Ports") or {},
                "mounts": [{
                    "type": mount.get("Type"),
                    "source": mount.get("Source"),
                    "destination": mount.get("Destination"),
                    "writable": bool(mount.get("RW")),
                } for mount in attrs.get("Mounts", [])],
            })
        return result

    def action(self, container_id: str, action: str) -> None:
        container = self.client.containers.get(container_id)
        if action == "start":
            container.start()
        elif action == "stop":
            container.stop(timeout=10)
        elif action == "restart":
            container.restart(timeout=10)
        else:
            raise ValueError("不支持的容器操作")

    def exec_command(self, container_id: str, command: str) -> dict:
        command = (command or "").strip()
        if not command:
            raise ValueError("容器命令不能为空")
        if "\x00" in command or len(command) > COMMAND_MAX_LENGTH:
            raise ValueError(f"容器命令不能超过 {COMMAND_MAX_LENGTH} 个字符")

        container = self.client.containers.get(container_id)
        if container.status != "running":
            raise ValueError("只能在运行中的容器执行命令")
        self._assert_exec_mounts_are_safe(container)

        wrapper = (
            'command -v timeout >/dev/null 2>&1 || '
            '{ echo "container does not provide the timeout command" >&2; exit 127; }; '
            f'exec timeout -k 2 {COMMAND_TIMEOUT_SECONDS} sh -lc "$1"'
        )
        started = time.monotonic()
        result = container.exec_run(["sh", "-c", wrapper, "sh", command], demux=True)
        stdout, stderr = result.output if hasattr(result, "output") else result[1]
        stdout_text, stdout_truncated = self._decode_command_output(stdout or b"")
        stderr_text, stderr_truncated = self._decode_command_output(stderr or b"")
        return {
            "exit_code": int(result.exit_code),
            "stdout": stdout_text,
            "stderr": stderr_text,
            "truncated": stdout_truncated or stderr_truncated,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }

    @staticmethod
    def _assert_exec_mounts_are_safe(container) -> None:
        for mount in container.attrs.get("Mounts", []) or []:
            source = str(mount.get("Source") or "")
            destination = str(mount.get("Destination") or "")
            writable = bool(mount.get("RW"))
            if source == "/var/run/docker.sock" or destination == "/var/run/docker.sock":
                raise ValueError("该容器挂载了 Docker Socket，禁止远程执行命令")
            if writable and source == "/":
                raise ValueError("该容器可写挂载宿主机根目录，禁止远程执行命令")

    @staticmethod
    def _decode_command_output(data: bytes) -> tuple[str, bool]:
        truncated = len(data) > COMMAND_OUTPUT_MAX_BYTES
        if truncated:
            data = data[:COMMAND_OUTPUT_MAX_BYTES]
        return data.decode("utf-8", "replace"), truncated

    def list_files(self, container_id: str, path: Optional[str] = "/") -> dict:
        path = posixpath.normpath("/" + (path or "/").lstrip("/"))
        container = self.client.containers.get(container_id)
        command = ["sh", "-c", 'find "$1" -mindepth 1 -maxdepth 1 -printf "%y\\t%s\\t%T@\\t%f\\n" 2>/dev/null', "sh", path]
        result = container.exec_run(command, demux=True)
        stdout, stderr = result.output if hasattr(result, "output") else result[1]
        if result.exit_code != 0:
            message = stderr.decode("utf-8", "replace").strip() if stderr else "无法读取目录"
            raise ValueError(message)
        entries = []
        for line in (stdout or b"").decode("utf-8", "replace").splitlines():
            kind, size, modified, name = line.split("\t", 3)
            entries.append({
                "name": name,
                "path": posixpath.join(path, name),
                "type": "directory" if kind == "d" else "file",
                "size": int(size),
                "modified": float(modified),
            })
        entries.sort(key=lambda item: (item["type"] != "directory", item["name"].lower()))
        return {"path": path, "parent": posixpath.dirname(path) if path != "/" else None, "entries": entries}
