import fcntl
import hashlib
import json
import math
import os
import re
import secrets
import shutil
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator


UPLOAD_ID_RE = re.compile(r"^[a-f0-9]{48}$")
CHUNK_FILE_RE = re.compile(r"^(\d{8})\.part$")


class ChunkUploadError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class ChunkUploadStore:
    def __init__(self, root_dir: str, chunk_size: int, max_age_seconds: int):
        self.root_dir = root_dir
        self.chunk_size = chunk_size
        self.max_age_seconds = max_age_seconds
        self._processor_id = f"{os.getpid()}:{secrets.token_hex(8)}"
        self._active_processing: set[str] = set()
        os.makedirs(self.root_dir, exist_ok=True)

    def create(
        self,
        *,
        filename: str,
        size: int,
        role: str,
        ttl_hours: int | None,
        max_bytes: int,
        owner_key: str,
    ) -> dict[str, Any]:
        if size <= 0:
            raise ChunkUploadError(400, "不能上传空文件")
        if size > max_bytes:
            raise ChunkUploadError(400, f"文件过大，超过 {max_bytes // 1024 // 1024} MB 限制")
        if role not in {"guest", "admin"}:
            raise ChunkUploadError(400, "上传角色非法")

        upload_id = secrets.token_hex(24)
        token = secrets.token_urlsafe(32)
        session_dir = self._session_dir(upload_id)
        os.makedirs(session_dir, mode=0o700)
        now = self._now_iso()
        manifest = {
            "version": 1,
            "upload_id": upload_id,
            "token_hash": self._token_hash(token),
            "filename": filename,
            "size": size,
            "chunk_size": self.chunk_size,
            "total_chunks": math.ceil(size / self.chunk_size),
            "role": role,
            "ttl_hours": ttl_hours,
            "owner_key": owner_key,
            "status": "uploading",
            "created_at": now,
            "updated_at": now,
        }
        with self._guard(upload_id):
            self._write_manifest_unlocked(upload_id, manifest)
        return {**self._public_status(manifest, []), "token": token}

    def status(self, upload_id: str, token: str) -> dict[str, Any]:
        with self._guard(upload_id):
            manifest = self._authorized_manifest_unlocked(upload_id, token)
            if manifest.get("status") == "processing" and upload_id not in self._active_processing:
                manifest["status"] = "failed"
                manifest["last_error"] = "服务器处理曾中断，可以重新完成上传"
                manifest.pop("processor_id", None)
                self._touch_unlocked(upload_id, manifest)
            if manifest.get("status") == "completed":
                try:
                    self._remove_payload_unlocked(upload_id)
                except OSError:
                    pass
            uploaded_chunks = self._uploaded_chunks_unlocked(upload_id, manifest)
            status = self._public_status(manifest, uploaded_chunks)
            status["assembled"] = self._assembled_ready_unlocked(upload_id, manifest)
            return status

    def write_chunk(
        self,
        upload_id: str,
        token: str,
        chunk_index: int,
        body: Iterator[bytes],
    ) -> dict[str, Any]:
        session_dir = self._session_dir(upload_id)
        target_path = self._chunk_path(upload_id, chunk_index)
        temp_path = os.path.join(session_dir, f".{chunk_index:08d}.{secrets.token_hex(6)}.tmp")
        written = 0
        try:
            with self._guard(upload_id):
                manifest = self._authorized_manifest_unlocked(upload_id, token)
                if manifest.get("status") not in {"uploading", "failed"}:
                    raise ChunkUploadError(409, "当前上传会话不能接收分片")
                expected_size = self._expected_chunk_size(manifest, chunk_index)
                with open(temp_path, "xb") as handle:
                    for block in body:
                        if not block:
                            continue
                        written += len(block)
                        if written > expected_size:
                            raise ChunkUploadError(400, "分片大小超过预期")
                        handle.write(block)
                    handle.flush()
                    os.fsync(handle.fileno())
                if written != expected_size:
                    raise ChunkUploadError(400, f"分片大小不正确：预期 {expected_size} 字节，收到 {written} 字节")
                if os.path.isfile(target_path) and os.path.getsize(target_path) == expected_size:
                    os.remove(temp_path)
                    already_received = True
                else:
                    os.replace(temp_path, target_path)
                    already_received = False
                manifest["status"] = "uploading"
                manifest.pop("last_error", None)
                self._touch_unlocked(upload_id, manifest)
                uploaded_chunks = self._uploaded_chunks_unlocked(upload_id, manifest)
                return {
                    "ok": True,
                    "chunk_index": chunk_index,
                    "already_received": already_received,
                    "uploaded_chunks": uploaded_chunks,
                }
        except OSError as exc:
            status_code = 507 if exc.errno == 28 else 409
            detail = "服务器磁盘空间不足" if exc.errno == 28 else "上传会话已变化，请重新查询状态"
            raise ChunkUploadError(status_code, detail) from exc
        finally:
            try:
                os.remove(temp_path)
            except FileNotFoundError:
                pass

    def begin_processing(self, upload_id: str, token: str) -> dict[str, Any]:
        with self._guard(upload_id):
            manifest = self._authorized_manifest_unlocked(upload_id, token)
            if manifest.get("status") == "completed":
                return self._public_status(manifest, [])
            if manifest.get("status") == "processing" and upload_id in self._active_processing:
                raise ChunkUploadError(409, "文件正在处理，请稍后查询结果")
            uploaded_chunks = self._uploaded_chunks_unlocked(upload_id, manifest)
            assembled_ready = self._assembled_ready_unlocked(upload_id, manifest)
            missing = sorted(set(range(manifest["total_chunks"])) - set(uploaded_chunks))
            if missing and not assembled_ready:
                raise ChunkUploadError(409, f"还有 {len(missing)} 个分片未上传")
            manifest["status"] = "processing"
            manifest["processor_id"] = self._processor_id
            manifest.pop("last_error", None)
            self._active_processing.add(upload_id)
            self._touch_unlocked(upload_id, manifest)
            return self._public_status(manifest, uploaded_chunks)

    def assemble(self, upload_id: str, token: str) -> tuple[str, str]:
        with self._guard(upload_id):
            manifest = self._authorized_manifest_unlocked(upload_id, token)
            if manifest.get("status") != "processing" or upload_id not in self._active_processing:
                raise ChunkUploadError(409, "上传会话不在处理状态")
            assembled_path = os.path.join(self._session_dir(upload_id), "assembled.upload")
            if self._assembled_ready_unlocked(upload_id, manifest):
                return assembled_path, self._sha256_file(assembled_path)
            uploaded_chunks = self._uploaded_chunks_unlocked(upload_id, manifest)
            if len(uploaded_chunks) != manifest["total_chunks"]:
                raise ChunkUploadError(409, "上传分片不完整")

            temp_path = assembled_path + f".{secrets.token_hex(6)}.tmp"
            sha256 = hashlib.sha256()
            written = 0
            try:
                with open(temp_path, "xb") as output:
                    for chunk_index in range(manifest["total_chunks"]):
                        with open(self._chunk_path(upload_id, chunk_index), "rb") as source:
                            while True:
                                block = source.read(1024 * 1024)
                                if not block:
                                    break
                                output.write(block)
                                sha256.update(block)
                                written += len(block)
                    output.flush()
                    os.fsync(output.fileno())
                if written != manifest["size"]:
                    raise ChunkUploadError(409, "合并后的文件大小不正确，请重新上传")
                os.replace(temp_path, assembled_path)
            except ChunkUploadError as exc:
                manifest["status"] = "failed"
                manifest["last_error"] = exc.detail
                manifest.pop("processor_id", None)
                self._active_processing.discard(upload_id)
                self._touch_unlocked(upload_id, manifest)
                raise
            finally:
                try:
                    os.remove(temp_path)
                except FileNotFoundError:
                    pass
            self._remove_chunks_unlocked(upload_id)
            self._touch_unlocked(upload_id, manifest)
            return assembled_path, sha256.hexdigest()

    def mark_failed(self, upload_id: str, token: str, detail: str) -> None:
        with self._guard(upload_id):
            manifest = self._authorized_manifest_unlocked(upload_id, token)
            manifest["status"] = "failed"
            manifest["last_error"] = detail
            manifest.pop("processor_id", None)
            self._active_processing.discard(upload_id)
            self._touch_unlocked(upload_id, manifest)

    def mark_completed(self, upload_id: str, token: str, result: dict[str, Any]) -> dict[str, Any]:
        with self._guard(upload_id):
            manifest = self._authorized_manifest_unlocked(upload_id, token)
            manifest["status"] = "completed"
            manifest["result"] = result
            manifest.pop("last_error", None)
            manifest.pop("processor_id", None)
            self._active_processing.discard(upload_id)
            self._touch_unlocked(upload_id, manifest)
            try:
                self._remove_payload_unlocked(upload_id)
            except OSError:
                pass
            return self._public_status(manifest, [])

    def delete(self, upload_id: str, token: str) -> None:
        with self._guard(upload_id):
            self._authorized_manifest_unlocked(upload_id, token)
            if upload_id in self._active_processing:
                raise ChunkUploadError(409, "文件正在处理，暂时不能取消")
            shutil.rmtree(self._session_dir(upload_id), ignore_errors=True)

    def cleanup_expired(self) -> int:
        removed = 0
        now = time.time()
        try:
            names = os.listdir(self.root_dir)
        except FileNotFoundError:
            return 0
        for upload_id in names:
            if not UPLOAD_ID_RE.fullmatch(upload_id) or upload_id in self._active_processing:
                continue
            session_dir = self._session_dir(upload_id)
            manifest_path = self._manifest_path(upload_id)
            try:
                age = now - os.path.getmtime(manifest_path if os.path.isfile(manifest_path) else session_dir)
            except OSError:
                continue
            if age <= self.max_age_seconds:
                continue
            try:
                with self._guard(upload_id):
                    if upload_id in self._active_processing:
                        continue
                    try:
                        current_age = now - os.path.getmtime(self._manifest_path(upload_id))
                    except OSError:
                        current_age = self.max_age_seconds + 1
                    if current_age <= self.max_age_seconds:
                        continue
                    shutil.rmtree(session_dir, ignore_errors=True)
                    removed += 1
            except ChunkUploadError:
                continue
        return removed

    def reserved_bytes(self) -> int:
        total = 0
        try:
            names = os.listdir(self.root_dir)
        except FileNotFoundError:
            return 0
        for upload_id in names:
            if not UPLOAD_ID_RE.fullmatch(upload_id):
                continue
            try:
                with open(self._manifest_path(upload_id), "r", encoding="utf-8") as handle:
                    manifest = json.load(handle)
                if manifest.get("status") in {"uploading", "processing", "failed"}:
                    total += max(0, int(manifest.get("size", 0)))
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
        return total

    def active_session_counts(self, owner_key: str) -> tuple[int, int]:
        total = 0
        owned = 0
        try:
            names = os.listdir(self.root_dir)
        except FileNotFoundError:
            return total, owned
        for upload_id in names:
            if not UPLOAD_ID_RE.fullmatch(upload_id):
                continue
            try:
                with open(self._manifest_path(upload_id), "r", encoding="utf-8") as handle:
                    manifest = json.load(handle)
                if manifest.get("status") not in {"uploading", "processing", "failed"}:
                    continue
                total += 1
                if secrets.compare_digest(str(manifest.get("owner_key", "")), owner_key):
                    owned += 1
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
        return total, owned

    @contextmanager
    def _guard(self, upload_id: str):
        session_dir = self._session_dir(upload_id)
        if not os.path.isdir(session_dir):
            raise ChunkUploadError(404, "上传会话不存在或已过期")
        lock_path = os.path.join(session_dir, ".lock")
        try:
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        except FileNotFoundError as exc:
            raise ChunkUploadError(404, "上传会话不存在或已过期") from exc
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    def _authorized_manifest_unlocked(self, upload_id: str, token: str) -> dict[str, Any]:
        manifest = self._read_manifest_unlocked(upload_id)
        supplied_hash = self._token_hash(token or "")
        if not secrets.compare_digest(supplied_hash, str(manifest.get("token_hash", ""))):
            raise ChunkUploadError(401, "上传会话凭据无效")
        return manifest

    def _read_manifest_unlocked(self, upload_id: str) -> dict[str, Any]:
        try:
            with open(self._manifest_path(upload_id), "r", encoding="utf-8") as handle:
                manifest = json.load(handle)
        except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
            raise ChunkUploadError(404, "上传会话不存在或已过期") from exc
        if manifest.get("upload_id") != upload_id:
            raise ChunkUploadError(409, "上传会话数据损坏")
        return manifest

    def _write_manifest_unlocked(self, upload_id: str, manifest: dict[str, Any]) -> None:
        path = self._manifest_path(upload_id)
        temp_path = path + f".{secrets.token_hex(6)}.tmp"
        try:
            with open(temp_path, "x", encoding="utf-8") as handle:
                json.dump(manifest, handle, ensure_ascii=False, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_path, 0o600)
            os.replace(temp_path, path)
        finally:
            try:
                os.remove(temp_path)
            except FileNotFoundError:
                pass

    def _touch_unlocked(self, upload_id: str, manifest: dict[str, Any]) -> None:
        manifest["updated_at"] = self._now_iso()
        self._write_manifest_unlocked(upload_id, manifest)

    def _uploaded_chunks_unlocked(self, upload_id: str, manifest: dict[str, Any]) -> list[int]:
        if self._assembled_ready_unlocked(upload_id, manifest):
            return list(range(manifest["total_chunks"]))
        uploaded = []
        try:
            names = os.listdir(self._session_dir(upload_id))
        except FileNotFoundError:
            return uploaded
        for name in names:
            match = CHUNK_FILE_RE.fullmatch(name)
            if not match:
                continue
            chunk_index = int(match.group(1))
            if chunk_index >= manifest["total_chunks"]:
                continue
            path = os.path.join(self._session_dir(upload_id), name)
            try:
                if os.path.getsize(path) == self._expected_chunk_size(manifest, chunk_index):
                    uploaded.append(chunk_index)
            except OSError:
                continue
        return sorted(uploaded)

    def _expected_chunk_size(self, manifest: dict[str, Any], chunk_index: int) -> int:
        if chunk_index < 0 or chunk_index >= manifest["total_chunks"]:
            raise ChunkUploadError(404, "分片序号超出范围")
        if chunk_index == manifest["total_chunks"] - 1:
            return manifest["size"] - chunk_index * manifest["chunk_size"]
        return manifest["chunk_size"]

    def _public_status(self, manifest: dict[str, Any], uploaded_chunks: list[int]) -> dict[str, Any]:
        payload = {
            "ok": True,
            "upload_id": manifest["upload_id"],
            "filename": manifest["filename"],
            "size": manifest["size"],
            "chunk_size": manifest["chunk_size"],
            "total_chunks": manifest["total_chunks"],
            "uploaded_chunks": uploaded_chunks,
            "role": manifest["role"],
            "status": manifest["status"],
            "updated_at": manifest["updated_at"],
        }
        if manifest.get("last_error"):
            payload["detail"] = manifest["last_error"]
        if manifest["role"] == "admin":
            payload["ttl_hours"] = manifest.get("ttl_hours")
        if manifest.get("result"):
            payload["result"] = manifest["result"]
        return payload

    def _remove_assembled_unlocked(self, upload_id: str) -> None:
        try:
            os.remove(os.path.join(self._session_dir(upload_id), "assembled.upload"))
        except FileNotFoundError:
            pass

    def _remove_chunks_unlocked(self, upload_id: str) -> None:
        for name in os.listdir(self._session_dir(upload_id)):
            if CHUNK_FILE_RE.fullmatch(name):
                try:
                    os.remove(os.path.join(self._session_dir(upload_id), name))
                except FileNotFoundError:
                    pass

    def _remove_payload_unlocked(self, upload_id: str) -> None:
        self._remove_assembled_unlocked(upload_id)
        for name in os.listdir(self._session_dir(upload_id)):
            if CHUNK_FILE_RE.fullmatch(name) or name.endswith(".tmp"):
                try:
                    os.remove(os.path.join(self._session_dir(upload_id), name))
                except FileNotFoundError:
                    pass

    def _assembled_ready_unlocked(self, upload_id: str, manifest: dict[str, Any]) -> bool:
        path = os.path.join(self._session_dir(upload_id), "assembled.upload")
        try:
            return os.path.isfile(path) and os.path.getsize(path) == manifest["size"]
        except OSError:
            return False

    @staticmethod
    def _sha256_file(path: str) -> str:
        sha256 = hashlib.sha256()
        with open(path, "rb") as handle:
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                sha256.update(block)
        return sha256.hexdigest()

    def _session_dir(self, upload_id: str) -> str:
        if not UPLOAD_ID_RE.fullmatch(upload_id or ""):
            raise ChunkUploadError(404, "上传会话不存在或已过期")
        return os.path.join(self.root_dir, upload_id)

    def _manifest_path(self, upload_id: str) -> str:
        return os.path.join(self._session_dir(upload_id), "session.json")

    def _chunk_path(self, upload_id: str, chunk_index: int) -> str:
        return os.path.join(self._session_dir(upload_id), f"{chunk_index:08d}.part")

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()
