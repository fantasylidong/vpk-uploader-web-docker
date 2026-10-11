import asyncio
import hashlib
import io
import json
import os
import shutil
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import httpx
from fastapi import UploadFile

from tests import test_upload_publication as publication
from tests.test_vpk_integrity import missing_outer_terminator
from app import main
from app.db import SessionLocal, Upload
from app.upload_records import read_record

map_bytes = publication.map_bytes


class UploadLifecycleTest(unittest.TestCase):
    upload = publication.UploadPublicationTest.upload

    def setUp(self):
        publication.UploadPublicationTest.setUp(self)
        shutil.rmtree(Path(main.UPLOAD_DIR) / '.upload-records', ignore_errors=True)
        main.set_guest_ttl_hours(72)

    def row(self, upload_id):
        with SessionLocal() as db:
            return db.get(Upload, upload_id)

    def test_rebuild_recovers_web_timestamps_then_expires_only_web(self):
        created = main.now_utc() - timedelta(hours=70)
        with patch.object(main, 'now_utc', return_value=created):
            result = self.upload(map_bytes())
        original = self.row(result['id'])
        manual = Path(main.UPLOAD_DIR) / 'manual.vpk'
        manual.write_bytes(map_bytes(b'VBSP-manual'))
        old = main.time.time() - 120
        os.utime(manual, (old, old))
        with SessionLocal() as db:
            db.query(Upload).delete()
            db.commit()
        stats = main.sync_sftp_uploads(now_ts=main.time.time() + 120)
        self.assertEqual(stats['errors'], 0)
        restored = self.row(result['id'])
        self.assertEqual(restored.role, 'guest')
        self.assertEqual(restored.created_at, original.created_at)
        self.assertEqual(restored.expires_at, original.expires_at)
        with patch.object(main, 'now_utc', return_value=created + timedelta(hours=73)):
            main.cleanup_expired()
        self.assertFalse((Path(main.UPLOAD_DIR) / result['stored_name']).exists())
        self.assertTrue(manual.exists())
        self.assertEqual(self.row(result['id']).status, 'deleted')
        self.assertEqual(read_record(main.UPLOAD_DIR, result['stored_name'])['upload']['status'], 'deleted')

    def test_touch_preserves_web_origin_and_expiry(self):
        result = self.upload(map_bytes())
        original = self.row(result['id'])
        path = Path(main.UPLOAD_DIR) / result['stored_name']
        touched = main.time.time() + 120
        os.utime(path, (touched, touched))
        stats = main.sync_sftp_uploads(now_ts=touched + 120)
        self.assertEqual(stats['existing'], 1)
        current = self.row(result['id'])
        self.assertEqual(current.role, 'guest')
        self.assertEqual(current.created_at, original.created_at)
        self.assertEqual(current.expires_at, original.expires_at)
        self.assertEqual(main._upload_origin(current), 'web')

    def test_dedup_does_not_adopt_sftp_overwrite_or_keep_old_delete_age(self):
        with patch.object(main, 'now_utc', return_value=main.now_utc() - timedelta(hours=48)):
            first = self.upload(map_bytes(b'VBSP-old'))
        path = Path(main.UPLOAD_DIR) / first['stored_name']
        replacement = map_bytes(b'VBSP-new')
        path.write_bytes(replacement)
        second = self.upload(replacement)
        self.assertNotEqual(first['id'], second['id'])
        self.assertEqual(path.read_bytes(), replacement)
        self.assertEqual(self.row(first['id']).sha256, first['sha256'])
        with self.assertRaises(main.HTTPException) as error:
            main.delete_upload_item(second['id'], sourcebans=True, expected_sha256=second['sha256'])
        self.assertEqual(error.exception.status_code, 403)
        with patch.object(main, 'now_utc', return_value=main.now_utc() + timedelta(hours=25)):
            repeated = self.upload(replacement)
            self.assertEqual(repeated['id'], second['id'])
            with self.assertRaises(main.HTTPException) as error:
                main.delete_upload_item(second['id'], sourcebans=True, expected_sha256=second['sha256'])
            self.assertEqual(error.exception.status_code, 403)

    def test_sftp_changed_during_publication_is_deferred(self):
        path = Path(main.UPLOAD_DIR) / 'manual.vpk'
        path.write_bytes(missing_outer_terminator(map_bytes()))
        old = main.time.time() - 120
        os.utime(path, (old, old))
        replacement = map_bytes(b'VBSP-new')
        real_flush = SessionLocal.class_.flush
        changed = False

        def change_during_flush(db, *args, **kwargs):
            nonlocal changed
            result = real_flush(db, *args, **kwargs)
            if not changed:
                path.write_bytes(replacement)
                changed = True
            return result

        with patch.object(SessionLocal.class_, 'flush', change_during_flush):
            stats = main.sync_sftp_uploads()
        self.assertEqual(stats['deferred'], 1)
        self.assertEqual(path.read_bytes(), replacement)
        with SessionLocal() as db:
            self.assertEqual(db.query(Upload).count(), 0)

    def test_sftp_is_processed_repaired_once_and_kept(self):
        source = Path(main.UPLOAD_DIR) / 'manual.v1.vpk'
        source.write_bytes(missing_outer_terminator(map_bytes()))
        old = main.time.time() - 120
        os.utime(source, (old, old))
        with patch.object(main, 'process_server_vpk', wraps=main.process_server_vpk) as build:
            self.assertEqual(main.sync_sftp_uploads()['imported'], 1)
            self.assertEqual(main.sync_sftp_uploads(now_ts=main.time.time() + 120)['existing'], 1)
            self.assertEqual(build.call_count, 1)
        with SessionLocal() as db:
            row = db.query(Upload).one()
            self.assertEqual(main._upload_origin(row), 'sftp')
            self.assertIsNone(row.expires_at)
            self.assertEqual(row.stored_name.count('.'), 1)
            self.assertEqual(json.loads(row.vpk_report)['server_build']['mode'], 'repaired')
            final_path = Path(main.UPLOAD_DIR) / row.stored_name
        self.assertFalse(source.exists())
        self.assertTrue(main.validate_vpk(str(final_path), main.RULES_FILE).ok)
        with patch.object(main, 'now_utc', return_value=main.now_utc() + timedelta(days=365)):
            main.cleanup_expired()
        self.assertTrue(final_path.exists())

    def test_healthy_sftp_is_readable_by_game_user(self):
        path = Path(main.UPLOAD_DIR) / 'private-mode.vpk'
        data = map_bytes()
        path.write_bytes(data)
        path.chmod(0o600)
        old = main.time.time() - 120
        os.utime(path, (old, old))
        self.assertEqual(main.sync_sftp_uploads()['imported'], 1)
        self.assertEqual(path.read_bytes(), data)
        self.assertTrue(path.stat().st_mode & 0o004)
        self.assertEqual(main.sync_sftp_uploads()['existing'], 1)

    def test_failed_delete_is_retried_without_sftp_reclassification(self):
        with patch.object(main, 'now_utc', return_value=main.now_utc() - timedelta(days=4)):
            result = self.upload(map_bytes())
        path = Path(main.UPLOAD_DIR) / result['stored_name']
        real_remove = main.os.remove

        def failed_remove(filename):
            if str(filename) == str(path):
                raise PermissionError('busy')
            return real_remove(filename)

        with patch.object(main.os, 'remove', side_effect=failed_remove):
            with self.assertLogs(main.logger, level='WARNING'):
                main.cleanup_expired()
        self.assertTrue(path.exists())
        self.assertEqual(self.row(result['id']).status, 'active')
        self.assertEqual(main.sync_sftp_uploads(now_ts=main.time.time() + 120)['existing'], 1)
        self.assertEqual(main._upload_origin(self.row(result['id'])), 'web')
        main.cleanup_expired()
        self.assertFalse(path.exists())

    def test_cleanup_does_not_delete_sftp_replacement_before_scan(self):
        with patch.object(main, 'now_utc', return_value=main.now_utc() - timedelta(days=4)):
            result = self.upload(map_bytes())
        path = Path(main.UPLOAD_DIR) / result['stored_name']
        path.write_bytes(map_bytes(b'VBSP-manual'))
        with self.assertLogs(main.logger, level='WARNING'):
            main.cleanup_expired()
        self.assertTrue(path.exists())
        self.assertEqual(main.sync_sftp_uploads(now_ts=main.time.time() + 120)['updated'], 1)
        self.assertEqual(main._upload_origin(self.row(result['id'])), 'sftp')
        self.assertIsNone(self.row(result['id']).expires_at)

    def test_background_loop_expires_maps_without_requests(self):
        async def exercise():
            with patch.object(main, 'sync_sftp_uploads', return_value=dict(imported=0, updated=0, errors=0)), \
                    patch.object(main, 'cleanup_expired') as cleanup, \
                    patch.object(main.asyncio, 'sleep', side_effect=asyncio.CancelledError):
                with self.assertRaises(asyncio.CancelledError):
                    await main._sftp_sync_loop()
                cleanup.assert_called_once()
        asyncio.run(exercise())

    def test_delete_api_checks_token_age_hash_and_sftp_protection(self):
        result = self.upload(map_bytes())
        created = main._as_aware_utc(self.row(result['id']).created_at)

        async def exercise():
            with patch.object(main, 'FEDERATION_API_TOKEN', 'test-token'):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url='http://node.test') as client:
                    url = f'/api/federation/uploads/{result["id"]}/delete-map'
                    body = {'sha256': result['sha256']}
                    headers = {'Authorization': 'Bearer test-token'}
                    self.assertEqual((await client.post(url, json=body)).status_code, 401)
                    with patch.object(main, 'now_utc', return_value=created + timedelta(hours=24, seconds=-1)):
                        self.assertEqual((await client.post(url, json=body, headers=headers)).status_code, 403)
                    with patch.object(main, 'now_utc', return_value=created + timedelta(hours=24)):
                        self.assertEqual((await client.post(url, json={'sha256': '0' * 64}, headers=headers)).status_code, 409)
                        with SessionLocal() as db:
                            row = db.get(Upload, result['id'])
                            row.uploader_ip = 'sftp'
                            db.commit()
                        self.assertEqual((await client.post(url, json=body, headers=headers)).status_code, 403)
                        with SessionLocal() as db:
                            row = db.get(Upload, result['id'])
                            row.uploader_ip = 'test'
                            db.commit()
                        self.assertEqual((await client.post(url, json=body, headers=headers)).status_code, 200)
        asyncio.run(exercise())
        self.assertFalse((Path(main.UPLOAD_DIR) / result['stored_name']).exists())

    def test_lan_replica_preserves_original_expiry(self):
        data = map_bytes()
        digest = hashlib.sha256(data).hexdigest()
        created = main.now_utc() - timedelta(hours=25)
        expires = main.now_utc() + timedelta(hours=2)
        from app.lan_replication import ReplicationArtifact
        artifact = ReplicationArtifact(17, 'map.vpk', 'map_server.vpk', '', len(data), digest,
                                      role='guest', source='web', created_at=created.isoformat(), expires_at=expires.isoformat())
        preflight = main._replication_preflight('node-a', {
            'source_node_id': 'node-a', 'lan_group': 'room-1', 'artifacts': [artifact.manifest_item()],
        })
        response = asyncio.run(main.receive_lan_replication_upload(
            None, 'node-a', preflight['reservation_id'], 17, 'map.vpk', digest, len(data),
            UploadFile(filename='map.vpk', file=io.BytesIO(data))))
        row = self.row(response['upload']['id'])
        self.assertEqual(row.role, 'guest')
        self.assertEqual(main._as_aware_utc(row.created_at), created)
        self.assertEqual(main._as_aware_utc(row.expires_at), expires)
        self.assertEqual(main._upload_origin(row), 'web')
        self.assertEqual(read_record(main.UPLOAD_DIR, row.stored_name)['upload']['expires_at'], row.expires_at)
        with patch.object(main, 'now_utc', return_value=expires + timedelta(seconds=1)):
            main.cleanup_expired()
        self.assertEqual(self.row(row.id).status, 'deleted')
