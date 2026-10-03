import asyncio
import concurrent.futures
import hashlib
import json
import os
import shutil
import struct
import tempfile
import threading
import time
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

import httpx
import tests._bootstrap  # noqa: F401
from app import main, vpk_tools
from app.db import SessionLocal, Upload
from app.vpk_reader import open_vpk


def vpk_bytes(entries):
    """Small VPK v1 fixtures, including names a local filesystem cannot represent."""
    tree = b''
    for path, data in entries:
        directory, filename = os.path.split(path)
        name, extension = os.path.splitext(filename)
        tree += extension[1:].encode() + b'\0' + (directory or ' ').encode() + b'\0' + name.encode() + b'\0'
        tree += struct.pack('<IHHIIH', zlib.crc32(data), len(data), 32767, 0, 0, 65535)
        tree += data + b'\0\0'
    tree += b'\0'
    return struct.pack('<III', 0x55aa1234, 1, len(tree)) + tree


def map_bytes(data=b'VBSP'):
    return vpk_bytes([('addoninfo.txt', b'AddonInfo {}'), ('maps/test.bsp', data)])


class UploadPublicationTest(unittest.TestCase):
    def setUp(self):
        with SessionLocal() as db:
            db.query(Upload).delete()
            db.query(main.ReplicationReservation).delete()
            db.query(main.AppSetting).delete()
            db.commit()
        for entry in Path(main.UPLOAD_DIR).iterdir():
            if entry.is_file():
                entry.unlink()
        self.source_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.source_dir.cleanup)
        self.sequence = 0

    def upload(self, data, name='same.vpk'):
        self.sequence += 1
        source = Path(self.source_dir.name) / f'{self.sequence}.vpk'
        source.write_bytes(data)
        return main._process_vpk_upload(
            'test', 'guest', None, str(source), name, hashlib.sha256(data).hexdigest(), {}, 1024
        )[1]

    def check_records(self, count):
        with SessionLocal() as db:
            rows = db.query(Upload).all()
            self.assertEqual(len(rows), count)
            for row in rows:
                path = Path(main.UPLOAD_DIR) / row.stored_name
                self.assertTrue(path.is_file())
                self.assertEqual(path.stat().st_size, row.size)
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), row.sha256)
                self.assertTrue(path.stat().st_mode & 0o004, 'game user must be able to read the published VPK')
        self.assertFalse(list(Path(main.UPLOAD_DIR).glob('.upload-*.part')))

    def test_same_name_concurrent_uploads_keep_all_successful_files(self):
        for identical in (True, False):
            with self.subTest(identical=identical):
                self.setUp()
                real_build = main.process_server_vpk
                built = threading.Barrier(2)
                build_lock = threading.Lock()
                paths = []

                def overlapping_build(**kwargs):
                    # Both builds finish before either may hash/publish; this exposed the old shared output path.
                    with build_lock:
                        result = real_build(**kwargs)
                        paths.append(result['server']['path'])
                    built.wait(timeout=5)
                    return result

                with patch.object(main, 'process_server_vpk', overlapping_build):
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                        first = pool.submit(self.upload, map_bytes(b'VBSP-a'))
                        second = pool.submit(self.upload, map_bytes(b'VBSP-a' if identical else b'VBSP-bb'))
                        results = [first.result(timeout=10), second.result(timeout=10)]
                self.assertEqual(len(set(paths)), 2, 'each build must own a private output file')
                self.assertEqual(len({r['id'] for r in results}), 1 if identical else 2)
                self.check_records(1 if identical else 2)

    def test_sftp_cannot_import_a_build_before_publication(self):
        real_build = main.process_server_vpk

        def scan_after_build(**kwargs):
            report = real_build(**kwargs)
            path = report['server']['path']
            old = time.time() - main.SFTP_IMPORT_MIN_AGE_SECONDS - 10
            os.utime(path, (old, old))
            self.assertEqual(main.sync_sftp_uploads()['imported'], 0)
            return report

        with patch.object(main, 'process_server_vpk', scan_after_build):
            result = self.upload(map_bytes())
        self.assertEqual(result['role'], 'guest')
        self.check_records(1)

    def test_sftp_rechecks_record_created_after_its_initial_scan(self):
        path = Path(main.UPLOAD_DIR) / 'published.vpk'
        path.write_bytes(map_bytes())
        old = time.time() - main.SFTP_IMPORT_MIN_AGE_SECONDS - 10
        os.utime(path, (old, old))
        real_hash = main._sha256_file

        def publish_record_during_hash(name):
            digest = real_hash(name)
            with main.capacity_guard(), SessionLocal() as db:
                db.add(Upload(original_name='source.vpk', stored_name=path.name, sha256=digest,
                              size=path.stat().st_size, role='guest', status='active', created_at=main.now_utc()))
                db.commit()
            return digest

        with patch.object(main, '_sha256_file', publish_record_during_hash):
            result = main.sync_sftp_uploads()
        self.assertEqual(result['errors'], 0)
        self.assertEqual(result['imported'], 0)
        with SessionLocal() as db:
            self.assertEqual(db.query(Upload).one().role, 'guest')
        self.check_records(1)

    def test_failed_commit_does_not_remove_another_upload(self):
        self.upload(map_bytes())
        with patch.object(SessionLocal.class_, 'commit', side_effect=RuntimeError('database unavailable')):
            with self.assertLogs(main.logger, level='ERROR') as logs:
                with self.assertRaisesRegex(RuntimeError, 'database unavailable'):
                    self.upload(map_bytes(b'VBSP-other'))
        self.assertIn('same.vpk', '\n'.join(logs.output))
        self.check_records(1)

    def test_response_failure_after_commit_preserves_published_file(self):
        with patch.object(SessionLocal.class_, 'refresh', side_effect=RuntimeError('read failed')):
            with self.assertLogs(main.logger, level='ERROR'):
                with self.assertRaisesRegex(RuntimeError, 'read failed'):
                    self.upload(map_bytes())
        self.check_records(1)

    def test_cleanup_skips_active_work_and_unrelated_directories(self):
        unrelated = Path(tempfile.mkdtemp(dir=main.TMP_DIR, prefix='other-'))
        self.addCleanup(shutil.rmtree, unrelated, True)
        old = time.time() - main.WORK_MAX_AGE_MIN * 60 - 10
        os.utime(unrelated, (old, old))
        real_filter = vpk_tools._filter_copy

        def cleanup_during_build(*args):
            result = real_filter(*args)
            work = Path(args[1]).parent
            os.utime(work, (old, old))
            main.cleanup_tmp_and_work()
            self.assertTrue(work.is_dir())
            self.assertTrue(unrelated.is_dir())
            return result

        with patch.object(vpk_tools, '_filter_copy', cleanup_during_build):
            result = self.upload(map_bytes())
        with open_vpk(str(Path(main.UPLOAD_DIR) / result['stored_name'])) as archive:
            self.assertIn('maps/test.bsp', list(archive))
        self.assertFalse(list(Path(main.TMP_DIR).glob('vpk-work-*')))
        self.check_records(1)

    def test_bad_archive_paths_and_long_names_are_http_400(self):
        cases = [
            ('conflict.vpk', vpk_bytes([('addoninfo.txt', b'AddonInfo {}'), ('maps/clash.txt', b'x'), ('maps/clash.txt/map.bsp', b'VBSP')])),
            ('longentry.vpk', vpk_bytes([('addoninfo.txt', b'AddonInfo {}'), ('maps/' + 'x' * 256 + '.bsp', b'VBSP')])),
            ('x' * 250 + '.vpk', map_bytes()),
            ('图' * 81 + '.vpk', map_bytes()),
        ]

        async def exercise():
            with patch.object(main, 'FEDERATION_API_TOKEN', 'test-token'):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app, raise_app_exceptions=False), base_url='http://uploader.test') as client:
                    for name, data in cases:
                        for endpoint in ('/upload', '/api/federation/uploads'):
                            response = await client.post(endpoint, headers={'Authorization': 'Bearer test-token'}, files={'file': (name, data)})
                            self.assertEqual(response.status_code, 400, (name, endpoint, response.text))
                            self.assertTrue(response.json()['detail'])
                        response = await client.post('/api/chunked-uploads', json={'filename': name, 'size': len(data), 'role': 'guest'})
                        if len(name.encode()) > 240:
                            self.assertEqual(response.status_code, 400)
                            continue
                        self.assertEqual(response.status_code, 201, response.text)
                        session = response.json()
                        url = '/api/chunked-uploads/' + session['upload_id']
                        headers = {'X-Upload-Token': session['token']}
                        await client.put(url + '/chunks/0', content=data, headers=headers)
                        response = await client.post(url + '/complete', headers=headers)
                        self.assertEqual(response.status_code, 400, response.text)
        asyncio.run(exercise())
        self.check_records(0)
        self.assertFalse(list(Path(main.TMP_DIR).glob('vpk-work-*')))

    def test_maximum_source_name_remains_valid_for_lan_replication(self):
        for name in ('x' * 236 + '.vpk', '图' * 78 + 'ab.vpk'):
            with self.subTest(name=name):
                self.assertEqual(len(name.encode()), 240)
                result = self.upload(map_bytes(name.encode()), name)
                self.assertEqual(len(result['stored_name'].encode()), 247)
                manifest = main._replication_manifest_items({'artifacts': [{**result, 'source_upload_id': result['id']}]})
                self.assertEqual(manifest[0]['stored_name'], result['stored_name'])
                self.assertEqual(main._ensure_vpk_filename(result['stored_name']), result['stored_name'])
        self.check_records(2)

    def test_dotted_names_are_mountable_without_changing_display_names(self):
        names = ('Utopia v1.1.vpk', 'SchoolLive!（V1.5）.VPK', 'map...beta.vpk', '图.' * 58 + 'x.vpk')
        for name in names:
            with self.subTest(name=name):
                result = self.upload(map_bytes(name.encode()), name)
                self.assertEqual(result['original_name'], name)
                self.assertEqual(result['stored_name'].count('.'), 1)
                self.assertTrue(result['stored_name'].endswith('_server.vpk'))
                self.assertLessEqual(len(result['stored_name'].encode()), 255)
        self.check_records(len(names))

    def test_dot_normalization_collisions_do_not_overwrite(self):
        first = self.upload(map_bytes(b'VBSP-first'), 'map.v1.vpk')
        second = self.upload(map_bytes(b'VBSP-second'), 'map_v1.vpk')
        self.assertEqual(first['stored_name'], 'map_v1_server.vpk')
        self.assertEqual(second['stored_name'], 'map_v1_2_server.vpk')
        self.check_records(2)

    def legacy_upload(self, data, name='Utopia v1.1.vpk'):
        result = self.upload(data, name)
        old_name = os.path.splitext(name)[0] + '_server.vpk'
        old_path = Path(main.UPLOAD_DIR) / old_name
        (Path(main.UPLOAD_DIR) / result['stored_name']).rename(old_path)
        with SessionLocal() as db:
            row = db.get(Upload, result['id'])
            row.stored_name = old_name
            report = json.loads(row.vpk_report)
            report['server_build']['server']['path'] = str(old_path)
            row.vpk_report = json.dumps(report)
            db.commit()
        return result, old_path

    def test_redeploy_replaces_legacy_dedup_target_without_moving_old_file(self):
        data = map_bytes()
        original, old_path = self.legacy_upload(data)
        result = self.upload(data, original['original_name'])
        self.assertFalse(result.get('deduplicated', False))
        self.assertNotEqual(result['id'], original['id'])
        self.assertEqual(result['original_name'], original['original_name'])
        self.assertEqual(result['sha256'], original['sha256'])
        self.assertEqual(result['stored_name'], 'Utopia v1_1_server.vpk')
        self.assertTrue(old_path.exists())
        with SessionLocal() as db:
            row = db.get(Upload, result['id'])
            self.assertEqual(json.loads(row.vpk_report)['server_build']['server']['path'],
                             str(Path(main.UPLOAD_DIR) / result['stored_name']))
            self.assertEqual(db.get(Upload, original['id']).stored_name, old_path.name)
        repeated = self.upload(data, original['original_name'])
        self.assertEqual(repeated['id'], result['id'])
        self.assertTrue(repeated['deduplicated'])
        self.check_records(2)

    def test_legacy_redeploy_commit_failure_preserves_old_file_and_database(self):
        data = map_bytes()
        original, old_path = self.legacy_upload(data)
        old_bytes = old_path.read_bytes()
        with patch.object(SessionLocal.class_, 'commit', side_effect=RuntimeError('database unavailable')):
            with self.assertLogs(main.logger, level='ERROR'):
                with self.assertRaisesRegex(RuntimeError, 'database unavailable'):
                    self.upload(data, original['original_name'])
        with SessionLocal() as db:
            self.assertEqual(db.get(Upload, original['id']).stored_name, old_path.name)
        self.assertEqual(old_path.read_bytes(), old_bytes)
        self.assertFalse((Path(main.UPLOAD_DIR) / original['stored_name']).exists())
        self.check_records(1)

    def test_legacy_redeploy_does_not_replace_normalized_name_collision(self):
        original, old_path = self.legacy_upload(map_bytes(b'VBSP-old'), 'map.v1.vpk')
        other = self.upload(map_bytes(b'VBSP-other'), 'map_v1.vpk')
        other_path = Path(main.UPLOAD_DIR) / other['stored_name']
        other_bytes = other_path.read_bytes()
        result = self.upload(map_bytes(b'VBSP-old'), 'map.v1.vpk')
        self.assertNotEqual(result['id'], original['id'])
        self.assertEqual(result['stored_name'], 'map_v1_2_server.vpk')
        self.assertEqual(other_path.read_bytes(), other_bytes)
        self.assertTrue(old_path.exists())
        self.check_records(3)

    def test_lan_preflight_does_not_reuse_legacy_name(self):
        original, old_path = self.legacy_upload(map_bytes())
        result = main._replication_preflight('node-a', {
            'source_node_id': 'node-a', 'lan_group': 'room-1',
            'artifacts': [{**original, 'stored_name': old_path.name, 'source_upload_id': 7}],
        })
        self.assertEqual(result['status'], 'reserved')
        self.assertEqual(result['required_bytes'], original['size'])
        self.assertEqual(result['already_present'], [])
        self.assertEqual(result['accepted'][0]['original_name'], original['original_name'])
        self.assertTrue(old_path.exists())
        self.check_records(1)

    def test_cleanup_removes_only_abandoned_work_and_partials(self):
        old = time.time() - max(main.WORK_MAX_AGE_MIN * 60, main.LAN_REPLICATION.reservation_ttl_seconds) - 10
        work = Path(tempfile.mkdtemp(prefix='vpk-work-', dir=main.TMP_DIR))
        (work / '.lock').touch()
        os.utime(work, (old, old))
        partial = Path(main.UPLOAD_DIR) / '.upload-abandoned.part'
        partial.write_bytes(b'old')
        os.utime(partial, (old, old))
        main.cleanup_tmp_and_work()
        self.assertFalse(work.exists())
        self.assertFalse(partial.exists())
