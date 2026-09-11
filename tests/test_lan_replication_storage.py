import asyncio
import hashlib
import io
import json
import os
import shutil
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx


from tests._bootstrap import DATA_DIR as TEST_DATA_DIR  # noqa: E402  必须先于 app.main 导入

from starlette.datastructures import UploadFile  # noqa: E402

from app import main  # noqa: E402
from app.db import ReplicationReservation, SessionLocal, Upload  # noqa: E402
from app.vpkcheck import ValidationResult  # noqa: E402


def valid_result() -> ValidationResult:
    return ValidationResult(
        ok=True,
        size_mb=0,
        max_size_mb=1024,
        required_present=["addoninfo.txt"],
        missing_required=[],
        blocked_hits=[],
        warned_hits=[],
        file_count=1,
        sample_files=["addoninfo.txt"],
    )


class LanReplicationStorageTest(unittest.TestCase):
    def setUp(self):
        db = SessionLocal()
        try:
            db.query(ReplicationReservation).delete()
            db.query(Upload).delete()
            db.query(main.AppSetting).delete()
            db.commit()
        finally:
            db.close()
        for name in os.listdir(main.UPLOAD_DIR):
            path = os.path.join(main.UPLOAD_DIR, name)
            if os.path.isfile(path):
                os.remove(path)
        shutil.rmtree(main.CHUNK_UPLOAD_DIR, ignore_errors=True)
        main.CHUNK_UPLOAD_STORE = main.ChunkUploadStore(
            main.CHUNK_UPLOAD_DIR,
            chunk_size=main.CHUNK_UPLOAD_SIZE_MB * 1024 * 1024,
            max_age_seconds=main.CHUNK_UPLOAD_MAX_AGE_HOURS * 60 * 60,
        )
        main.set_total_upload_limit_mb(0)

    def _payload(self, data: bytes, sha256: str | None = None):
        digest = sha256 or hashlib.sha256(data).hexdigest()
        return {
            "source_node_id": "node-a",
            "lan_group": "room-1",
            "artifacts": [{
                "source_upload_id": 7,
                "original_name": "map.vpk",
                "stored_name": "map_server.vpk",
                "size": len(data),
                "sha256": digest,
            }],
        }

    def test_lan_api_requires_cidr_token_and_matching_group(self):
        async def request_capabilities():
            transport = httpx.ASGITransport(app=main.app, client=("10.20.0.5", 51000))
            async with httpx.AsyncClient(transport=transport, base_url="http://uploader.test") as client:
                missing_token = await client.get(
                    "/api/lan/replication/capabilities",
                    headers={"X-LAN-Group": "room-1", "X-LAN-Node": "node-a"},
                )
                wrong_group = await client.get(
                    "/api/lan/replication/capabilities",
                    headers={
                        "Authorization": "Bearer " + "b" * 64,
                        "X-LAN-Group": "another-room",
                        "X-LAN-Node": "node-a",
                    },
                )
                accepted = await client.get(
                    "/api/lan/replication/capabilities",
                    headers={
                        "Authorization": "Bearer " + "b" * 64,
                        "X-LAN-Group": "room-1",
                        "X-LAN-Node": "node-a",
                    },
                )
                return missing_token, wrong_group, accepted

        missing_token, wrong_group, accepted = asyncio.run(request_capabilities())
        self.assertEqual(missing_token.status_code, 401)
        self.assertEqual(wrong_group.status_code, 409)
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(accepted.json()["node_id"], "node-b")

    def test_preflight_reserves_capacity_and_completion_releases_it(self):
        data = b"server-vpk"
        result = main._replication_preflight("node-a", self._payload(data))

        self.assertEqual(result["status"], "reserved")
        self.assertEqual(result["required_bytes"], len(data))
        self.assertGreaterEqual(result["storage"]["reserved_bytes"], len(data))

        completed = main.complete_lan_replication_reservation("node-a", result["reservation_id"])
        self.assertEqual(completed["status"], "partial")
        self.assertEqual(completed["released_item_count"], 1)

        db = SessionLocal()
        try:
            self.assertEqual(main.active_replication_reserved_bytes(db), 0)
        finally:
            db.close()

    def test_cleanup_removes_stale_lan_partial_file(self):
        partial_path = os.path.join(main.UPLOAD_DIR, ".lan-stale.part")
        with open(partial_path, "wb") as handle:
            handle.write(b"partial")
        stale_time = main.time.time() - main.LAN_REPLICATION.reservation_ttl_seconds - 10
        os.utime(partial_path, (stale_time, stale_time))

        main.cleanup_tmp_and_work()
        self.assertFalse(os.path.exists(partial_path))

    def test_sftp_scan_imports_existing_vpk_once(self):
        path = os.path.join(main.UPLOAD_DIR, "sftp-map.vpk")
        with open(path, "wb") as handle:
            handle.write(b"existing-vpk")
        old_time = main.time.time() - main.SFTP_IMPORT_MIN_AGE_SECONDS - 1
        os.utime(path, (old_time, old_time))

        first = main.sync_sftp_uploads()
        second = main.sync_sftp_uploads()

        self.assertEqual(first["imported"], 1)
        self.assertEqual(first["errors"], 0)
        self.assertEqual(second["imported"], 0)
        self.assertEqual(second["existing"], 1)

        db = SessionLocal()
        try:
            uploads = db.query(Upload).filter(Upload.stored_name == "sftp-map.vpk").all()
            self.assertEqual(len(uploads), 1)
            self.assertEqual(uploads[0].role, "admin")
            self.assertEqual(uploads[0].status, "active")
            self.assertIsNone(uploads[0].expires_at)
            self.assertEqual(uploads[0].sha256, hashlib.sha256(b"existing-vpk").hexdigest())
        finally:
            db.close()

    def test_sftp_scan_defers_file_changed_while_hashing(self):
        path = os.path.join(main.UPLOAD_DIR, "changing.vpk")
        with open(path, "wb") as handle:
            handle.write(b"first")
        old_time = main.time.time() - main.SFTP_IMPORT_MIN_AGE_SECONDS - 1
        os.utime(path, (old_time, old_time))

        def change_during_hash(file_path):
            with open(file_path, "ab") as handle:
                handle.write(b"-changed")
            return hashlib.sha256(b"first").hexdigest()

        with patch.object(main, "_sha256_file", side_effect=change_during_hash):
            stats = main.sync_sftp_uploads()

        self.assertEqual(stats["deferred"], 1)
        db = SessionLocal()
        try:
            self.assertEqual(db.query(Upload).filter(Upload.stored_name == "changing.vpk").count(), 0)
        finally:
            db.close()

    def test_preflight_skips_node_when_quota_is_too_small(self):
        main.set_total_upload_limit_mb(1)
        db = SessionLocal()
        try:
            db.add(Upload(
                original_name="existing.vpk",
                stored_name="existing_server.vpk",
                sha256="0" * 64,
                size=900 * 1024,
                role="admin",
                created_at=main.now_utc(),
                expires_at=None,
                vpk_valid=True,
                vpk_report="{}",
                status="active",
                uploader_ip="test",
            ))
            db.commit()
        finally:
            db.close()

        result = main._replication_preflight("node-a", self._payload(b"x" * (200 * 1024)))
        self.assertEqual(result["status"], "insufficient_capacity")
        self.assertEqual(result["accepted"], [])
        self.assertEqual(result["storage"]["available_bytes"], 124 * 1024)

    def test_receive_validates_hash_stores_once_and_deduplicates(self):
        data = b"server-vpk-content"
        sha256 = hashlib.sha256(data).hexdigest()
        preflight = main._replication_preflight("node-a", self._payload(data, sha256))
        upload_file = UploadFile(filename="map_server.vpk", file=io.BytesIO(data))

        with patch.object(main, "validate_vpk", return_value=valid_result()):
            stored = asyncio.run(main.receive_lan_replication_upload(
                request=None,
                source_node_id="node-a",
                reservation_id=preflight["reservation_id"],
                source_upload_id=7,
                original_name="map.vpk",
                expected_sha256=sha256,
                expected_size=len(data),
                file=upload_file,
            ))

        self.assertEqual(stored["status"], "stored")
        target_path = os.path.join(main.UPLOAD_DIR, stored["upload"]["stored_name"])
        with open(target_path, "rb") as handle:
            self.assertEqual(handle.read(), data)

        duplicate = main._replication_preflight("node-a", self._payload(data, sha256))
        self.assertEqual(duplicate["status"], "already_present")
        self.assertEqual(duplicate["required_bytes"], 0)

        db = SessionLocal()
        try:
            uploads = db.query(Upload).filter(Upload.status == "active").all()
            self.assertEqual(len(uploads), 1)
            self.assertEqual(uploads[0].sha256, sha256)
            report = json.loads(uploads[0].vpk_report)
            self.assertEqual(report["upload_source"]["source_node_id"], "node-a")
        finally:
            db.close()

    def test_chunked_upload_resumes_out_of_order_and_completes_once(self):
        chunk_size = main.CHUNK_UPLOAD_STORE.chunk_size
        first_chunk = b"a" * chunk_size
        last_chunk = b"end"
        total_size = len(first_chunk) + len(last_chunk)

        async def exercise():
            transport = httpx.ASGITransport(app=main.app, client=("127.0.0.1", 51000))
            async with httpx.AsyncClient(transport=transport, base_url="http://uploader.test") as client:
                created = await client.post("/api/chunked-uploads", json={
                    "filename": "resume.vpk",
                    "size": total_size,
                    "role": "guest",
                })
                self.assertEqual(created.status_code, 201)
                session = created.json()
                headers = {"X-Upload-Token": session["token"]}

                uploaded_last = await client.put(
                    f"/api/chunked-uploads/{session['upload_id']}/chunks/1",
                    headers=headers,
                    content=last_chunk,
                )
                self.assertEqual(uploaded_last.status_code, 200)

                missing = await client.post(
                    f"/api/chunked-uploads/{session['upload_id']}/complete",
                    headers=headers,
                )
                self.assertEqual(missing.status_code, 409)

                resumed_store = main.ChunkUploadStore(
                    main.CHUNK_UPLOAD_DIR,
                    chunk_size=chunk_size,
                    max_age_seconds=main.CHUNK_UPLOAD_MAX_AGE_HOURS * 60 * 60,
                )
                resumed = resumed_store.status(session["upload_id"], session["token"])
                self.assertEqual(resumed["uploaded_chunks"], [1])

                wrong_token = await client.get(
                    f"/api/chunked-uploads/{session['upload_id']}",
                    headers={"X-Upload-Token": "wrong"},
                )
                self.assertEqual(wrong_token.status_code, 401)

                uploaded_first = await client.put(
                    f"/api/chunked-uploads/{session['upload_id']}/chunks/0",
                    headers=headers,
                    content=first_chunk,
                )
                self.assertEqual(uploaded_first.status_code, 200)
                status = await client.get(
                    f"/api/chunked-uploads/{session['upload_id']}",
                    headers=headers,
                )
                self.assertEqual(status.json()["uploaded_chunks"], [0, 1])

                main.CHUNK_UPLOAD_STORE.begin_processing(session["upload_id"], session["token"])
                concurrent = await client.post(
                    f"/api/chunked-uploads/{session['upload_id']}/complete",
                    headers=headers,
                )
                self.assertEqual(concurrent.status_code, 202)
                self.assertEqual(concurrent.json()["status"], "processing")
                main.CHUNK_UPLOAD_STORE.mark_failed(session["upload_id"], session["token"], "retry")

                item_result = {
                    "id": 91,
                    "original_name": "resume.vpk",
                    "stored_name": "resume_server.vpk",
                    "sha256": "1" * 64,
                    "size": 123,
                    "size_label": "0.00 MB",
                    "detail_url": "/detail/91",
                    "download_url": "/d/91",
                }
                handler = AsyncMock(return_value=(
                    [SimpleNamespace(id=91)],
                    {"uploaded": [item_result], "failed": []},
                    None,
                ))
                with patch.object(main, "_handle_upload", new=handler):
                    completed = await client.post(
                        f"/api/chunked-uploads/{session['upload_id']}/complete",
                        headers=headers,
                    )
                    repeated = await client.post(
                        f"/api/chunked-uploads/{session['upload_id']}/complete",
                        headers=headers,
                    )

                self.assertEqual(completed.status_code, 200)
                self.assertEqual(completed.json()["redirect_url"], "/detail/91")
                self.assertEqual(repeated.json(), completed.json())
                self.assertEqual(handler.await_count, 1)
                final_status = await client.get(
                    f"/api/chunked-uploads/{session['upload_id']}",
                    headers=headers,
                )
                self.assertEqual(final_status.json()["status"], "completed")

        asyncio.run(exercise())

    def test_chunked_admin_session_requires_login_on_every_request(self):
        async def exercise():
            transport = httpx.ASGITransport(app=main.app, client=("127.0.0.1", 51000))
            async with httpx.AsyncClient(transport=transport, base_url="http://uploader.test") as client:
                denied = await client.post("/api/chunked-uploads", json={
                    "filename": "admin.vpk",
                    "size": 4,
                    "role": "admin",
                    "ttl_hours": 0,
                })
                self.assertEqual(denied.status_code, 401)

                client.cookies.set("session", main.signer.dumps({"role": "admin"}))
                created = await client.post("/api/chunked-uploads", json={
                    "filename": "admin.vpk",
                    "size": 4,
                    "role": "admin",
                    "ttl_hours": 0,
                })
                self.assertEqual(created.status_code, 201)
                session = created.json()
                headers = {"X-Upload-Token": session["token"]}

                client.cookies.clear()
                denied_chunk = await client.put(
                    f"/api/chunked-uploads/{session['upload_id']}/chunks/0",
                    headers=headers,
                    content=b"vpk!",
                )
                self.assertEqual(denied_chunk.status_code, 401)

                client.cookies.set("session", main.signer.dumps({"role": "admin"}))
                accepted_chunk = await client.put(
                    f"/api/chunked-uploads/{session['upload_id']}/chunks/0",
                    headers=headers,
                    content=b"vpk!",
                )
                self.assertEqual(accepted_chunk.status_code, 200)
                cancelled = await client.delete(
                    f"/api/chunked-uploads/{session['upload_id']}",
                    headers=headers,
                )
                self.assertEqual(cancelled.status_code, 200)
                missing = await client.get(
                    f"/api/chunked-uploads/{session['upload_id']}",
                    headers=headers,
                )
                self.assertEqual(missing.status_code, 404)

        asyncio.run(exercise())

    def test_chunked_upload_rejects_oversize_before_receiving_chunks(self):
        main.set_upload_max_mb(1)

        async def exercise():
            transport = httpx.ASGITransport(app=main.app, client=("127.0.0.1", 51000))
            async with httpx.AsyncClient(transport=transport, base_url="http://uploader.test") as client:
                response = await client.post("/api/chunked-uploads", json={
                    "filename": "large.vpk",
                    "size": 1024 * 1024 + 1,
                    "role": "guest",
                })
                self.assertEqual(response.status_code, 400)
                self.assertIn("文件过大", response.json()["detail"])

        asyncio.run(exercise())

    def test_chunked_upload_sessions_reserve_total_capacity(self):
        main.set_total_upload_limit_mb(1)

        async def exercise():
            transport = httpx.ASGITransport(app=main.app, client=("127.0.0.1", 51000))
            async with httpx.AsyncClient(transport=transport, base_url="http://uploader.test") as client:
                first = await client.post("/api/chunked-uploads", json={
                    "filename": "first.vpk",
                    "size": 700 * 1024,
                    "role": "guest",
                })
                second = await client.post("/api/chunked-uploads", json={
                    "filename": "second.vpk",
                    "size": 400 * 1024,
                    "role": "guest",
                })
                self.assertEqual(first.status_code, 201)
                self.assertEqual(second.status_code, 400)
                self.assertIn("总容量", second.json()["detail"])

                db = SessionLocal()
                try:
                    self.assertIsNotNone(main.total_capacity_error(db, 400 * 1024))
                    snapshot = main.replication_storage_snapshot(db)
                    self.assertEqual(snapshot["chunk_reserved_bytes"], 700 * 1024)
                    self.assertEqual(snapshot["quota_available_bytes"], 324 * 1024)
                finally:
                    db.close()

        asyncio.run(exercise())

    def test_chunk_store_restart_uses_durable_assembled_file(self):
        root = os.path.join(TEST_DATA_DIR, "restart-store")
        store = main.ChunkUploadStore(root, chunk_size=4, max_age_seconds=3600)
        session = store.create(
            filename="restart.vpk",
            size=7,
            role="guest",
            ttl_hours=None,
            max_bytes=1024,
            owner_key="test",
        )
        store.write_chunk(session["upload_id"], session["token"], 1, iter([b"end"]))
        store.write_chunk(session["upload_id"], session["token"], 0, iter([b"data"]))
        store.begin_processing(session["upload_id"], session["token"])
        assembled_path, digest = store.assemble(session["upload_id"], session["token"])

        restarted = main.ChunkUploadStore(root, chunk_size=4, max_age_seconds=3600)
        status = restarted.status(session["upload_id"], session["token"])
        self.assertEqual(status["status"], "failed")
        self.assertTrue(status["assembled"])
        self.assertEqual(status["uploaded_chunks"], [0, 1])
        restarted.begin_processing(session["upload_id"], session["token"])
        resumed_path, resumed_digest = restarted.assemble(session["upload_id"], session["token"])
        self.assertEqual(resumed_path, assembled_path)
        self.assertEqual(resumed_digest, digest)

        result = {"ok": True, "status": "completed", "uploaded": [], "failed": [], "redirect_url": "/"}
        with patch.object(restarted, "_remove_payload_unlocked", side_effect=OSError("simulated crash")):
            restarted.mark_completed(session["upload_id"], session["token"], result)
        after_crash = main.ChunkUploadStore(root, chunk_size=4, max_age_seconds=3600)
        completed = after_crash.status(session["upload_id"], session["token"])
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["result"], result)

    def test_chunk_delete_waits_for_inflight_commit(self):
        root = os.path.join(TEST_DATA_DIR, "delete-race-store")
        store = main.ChunkUploadStore(root, chunk_size=4, max_age_seconds=3600)
        session = store.create(
            filename="race.vpk",
            size=4,
            role="guest",
            ttl_hours=None,
            max_bytes=1024,
            owner_key="test",
        )
        started = threading.Event()
        delete_started = threading.Event()
        release = threading.Event()
        errors = []

        def slow_body():
            started.set()
            release.wait(timeout=2)
            yield b"vpk!"

        def write_chunk():
            try:
                store.write_chunk(session["upload_id"], session["token"], 0, slow_body())
            except Exception as exc:
                errors.append(exc)

        def delete_session():
            try:
                delete_started.set()
                store.delete(session["upload_id"], session["token"])
            except Exception as exc:
                errors.append(exc)

        writer = threading.Thread(target=write_chunk)
        deleter = threading.Thread(target=delete_session)
        writer.start()
        self.assertTrue(started.wait(timeout=1))
        deleter.start()
        self.assertTrue(delete_started.wait(timeout=1))
        self.assertTrue(deleter.is_alive())
        release.set()
        writer.join(timeout=2)
        deleter.join(timeout=2)
        self.assertEqual(errors, [])
        self.assertFalse(os.path.exists(os.path.join(root, session["upload_id"])))


if __name__ == "__main__":
    unittest.main()
