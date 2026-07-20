import asyncio
import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

import httpx


TEST_DATA_DIR = tempfile.mkdtemp(prefix="vpk-uploader-lan-test-")
os.environ["DATA_DIR"] = TEST_DATA_DIR
os.environ["TMP_DIR"] = os.path.join(TEST_DATA_DIR, "tmp")
os.environ["LAN_NODE_ID"] = "node-b"
os.environ["LAN_GROUP"] = "room-1"
os.environ["LAN_PEER_API_TOKEN"] = "b" * 64
os.environ["LAN_PEER_ALLOWED_CIDRS"] = "10.20.0.0/24"
os.environ["LAN_DISK_RESERVE_MB"] = "0"

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
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)

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


if __name__ == "__main__":
    unittest.main()
