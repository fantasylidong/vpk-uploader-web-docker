import asyncio
import hashlib
import io
import json
import os
import struct
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

import httpx
from fastapi import UploadFile

from tests import test_upload_publication as publication
from app import main, vpk_tools
from app.db import SessionLocal, Upload
from app.vpk_reader import open_vpk
from app.vpk_integrity import inspect_vpk
from app.vpkcheck import validate_vpk


def payload_vpk(entries, version=1):
    tree, payload, offsets = bytearray(), bytearray(), {}
    header_size = 12 if version == 1 else 28
    for path, preload, body in entries:
        directory, filename = os.path.split(path)
        name, extension = os.path.splitext(filename)
        tree.extend(extension[1:].encode() + b'\0' + (directory or ' ').encode() + b'\0' + name.encode() + b'\0')
        offsets[path] = header_size + len(tree)
        tree.extend(struct.pack('<IHHIIH', zlib.crc32(preload + body), len(preload),
                                0x7fff, len(payload), len(body), 0xffff))
        tree.extend(preload + b'\0\0')
        payload.extend(body)
    tree.extend(b'\0')
    if version == 1:
        return struct.pack('<III', 0x55aa1234, 1, len(tree)) + tree + payload, offsets
    header = struct.pack('<7I', 0x55aa1234, 2, len(tree), len(payload), 0, 48, 0)
    prefix = header + tree + payload
    hashes = hashlib.md5(tree).digest() + hashlib.md5(b'').digest()
    return prefix + hashes + hashlib.md5(prefix + hashes).digest(), offsets


def missing_outer_terminator(data):
    data = bytearray(data)
    tree_size, = struct.unpack_from('<I', data, 8)
    del data[12 + tree_size - 1]
    struct.pack_into('<I', data, 8, tree_size - 1)
    return bytes(data)


class VPKIntegrityTest(unittest.TestCase):
    setUp = publication.UploadPublicationTest.setUp
    upload = publication.UploadPublicationTest.upload
    check_records = publication.UploadPublicationTest.check_records

    def source(self, data):
        path = Path(self.source_dir.name) / 'check.vpk'
        path.write_bytes(data)
        return str(path)

    def test_healthy_v1_v2_keep_preload_payload_and_original_bytes(self):
        entries = [('addoninfo.txt', b'Addon', b'Info {}'), ('maps/test.bsp', b'VBSP', b'payload')]
        for version in (1, 2):
            with self.subTest(version=version):
                data, _ = payload_vpk(entries, version)
                validation = validate_vpk(self.source(data), main.RULES_FILE)
                self.assertEqual(validation.repairable_issues, [])
                result = self.upload(data, f'v{version}.vpk')
                self.assertEqual((Path(main.UPLOAD_DIR) / result['stored_name']).read_bytes(), data)
        self.check_records(2)

    def test_missing_terminator_is_repacked_without_losing_resources(self):
        entries = [('addoninfo.txt', b'Addon', b'Info {}'),
                   ('maps/测试.bsp', b'VBSP', b'map' * 4096),
                   ('models/door.mdl', b'IDST', b'model' * 4096),
                   ('materials/door.vtf', b'VTF', b'texture'),
                   ('scripts/vscripts/door.nut', b'', b'print("door")')]
        data, _ = payload_vpk(entries)
        broken = missing_outer_terminator(data)
        path = self.source(broken)
        with self.assertRaisesRegex(ValueError, '无法部署'):
            validate_vpk(path, main.RULES_FILE)
        self.assertTrue(validate_vpk(path, main.RULES_FILE, allow_repair=True).repairable_issues)
        self.assertEqual(Path(path).read_bytes(), broken)
        result = self.upload(broken)
        output = Path(main.UPLOAD_DIR) / result['stored_name']
        self.assertTrue(validate_vpk(str(output), main.RULES_FILE).ok)
        with open_vpk(str(output)) as archive:
            self.assertEqual(set(archive), {entry[0] for entry in entries})
            for name, preload, body in entries:
                with archive.get_file(name) as entry:
                    self.assertEqual(entry.read(), preload + body)
                    self.assertTrue(entry.verify())
        with SessionLocal() as db:
            report = json.loads(db.get(Upload, result['id']).vpk_report)
            self.assertEqual(report['server_build']['mode'], 'repaired')
            self.assertTrue(report['server_build']['repairs'])
            self.assertEqual(report['server_build']['server']['removed'], 0)
        self.assertEqual(self.upload(broken)['id'], result['id'])
        self.check_records(1)

    def test_only_zero_padding_can_be_discarded(self):
        data = publication.map_bytes()
        for padding in (b'\0\0', b'unknown record'):
            bad = bytearray(data + padding)
            struct.pack_into('<I', bad, 8, len(bad) - 12)
            if padding.strip(b'\0'):
                with self.assertRaises(main.HTTPException):
                    self.upload(bytes(bad))
            else:
                self.upload(bytes(bad))
        self.check_records(1)

    def test_corrupt_data_and_ambiguous_structures_never_repair(self):
        data, offsets = payload_vpk([('addoninfo.txt', b'Addon', b'Info {}'),
                                     ('maps/test.bsp', b'VBSP', b'payload')])
        meta = offsets['maps/test.bsp']
        cases = []
        for offset, fmt, value in ((meta, '<I', 0), (meta + 6, '<H', 0),
                                   (meta + 8, '<I', len(data)), (meta + 16, '<H', 0)):
            bad = bytearray(data)
            struct.pack_into(fmt, bad, offset, value)
            cases.append(bytes(bad))
        for end in (meta + 17, meta + 18 + 3):
            bad = bytearray(data[:end])
            struct.pack_into('<I', bad, 8, len(bad) - 12)
            cases.append(bytes(bad))
        cases.append(missing_outer_terminator(cases[0]))
        cases.append(publication.vpk_bytes([('addoninfo.txt', b'x'),
                                           ('Maps/test.bsp', b'a'), ('maps/test.bsp', b'b')]))
        for bad in cases:
            with self.subTest(data=bad[-16:]):
                for allow in (False, True):
                    with self.assertRaises(ValueError):
                        validate_vpk(self.source(bad), main.RULES_FILE, allow_repair=allow)
                with self.assertRaises(main.HTTPException) as error:
                    self.upload(bad)
                self.assertEqual(error.exception.status_code, 400)
                self.assertIn('地图有问题，无法部署', error.exception.detail)
        self.check_records(0)

    def test_v2_data_and_footer_boundaries_and_checksums(self):
        data, offsets = payload_vpk([('addoninfo.txt', b'Addon', b'Info {}'),
                                     ('maps/test.bsp', b'VBSP', b'payload')], version=2)
        cases = [data[:-1], data[:-1] + bytes([data[-1] ^ 1])]
        for offset, value in ((12, 1), (16, 1), (20, 47), (24, 1),
                              (offsets['maps/test.bsp'], zlib.crc32(b'payload'))):
            bad = bytearray(data)
            struct.pack_into('<I', bad, offset, value)
            cases.append(bytes(bad))
        for bad in cases:
            with self.subTest(data=bad[:28]):
                with self.assertRaises(ValueError):
                    validate_vpk(self.source(bad), main.RULES_FILE, allow_repair=True)

    def test_corruption_during_copy_cannot_publish(self):
        real_copy = vpk_tools.shutil.copyfile

        def bad_copy(src, dst):
            result = real_copy(src, dst)
            with open(dst, 'r+b') as output:
                output.truncate(15)
            return result

        with patch.object(vpk_tools.shutil, 'copyfile', bad_copy):
            with self.assertRaises(main.HTTPException):
                self.upload(publication.map_bytes())
        self.check_records(0)

    def test_lan_receiver_rejects_unrepaired_package_even_with_valid_sha(self):
        bad = missing_outer_terminator(publication.map_bytes())
        digest = hashlib.sha256(bad).hexdigest()
        reservation = main._replication_preflight('node-a', {
            'source_node_id': 'node-a', 'lan_group': 'room-1',
            'artifacts': [{'source_upload_id': 1, 'original_name': 'map.vpk',
                           'stored_name': 'map_server.vpk', 'sha256': digest, 'size': len(bad)}],
        })
        with self.assertRaises(main.HTTPException) as error:
            asyncio.run(main.receive_lan_replication_upload(
                None, 'node-a', reservation['reservation_id'], 1, 'map.vpk', digest, len(bad),
                UploadFile(filename='map.vpk', file=io.BytesIO(bad))))
        self.assertEqual(error.exception.status_code, 400)
        self.check_records(0)
        self.assertFalse(list(Path(main.UPLOAD_DIR).glob('.lan-*.part')))

    def test_public_and_federation_explain_bad_crc(self):
        bad = publication.map_bytes().replace(b'VBSP', b'FAIL')

        async def exercise():
            with patch.object(main, 'FEDERATION_API_TOKEN', 'test-token'):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url='http://uploader.test') as client:
                    for endpoint in ('/upload', '/api/federation/uploads'):
                        response = await client.post(endpoint, headers={'Authorization': 'Bearer test-token'},
                                                     files={'file': ('map.vpk', bad)})
                        self.assertEqual(response.status_code, 400)
                        self.assertIn('地图有问题，无法部署', response.json()['detail'])
                        self.assertIn('CRC', response.json()['detail'])
        asyncio.run(exercise())
        self.check_records(0)

    def test_shared_payload_cannot_amplify_validation_or_repacking(self):
        data, offsets = payload_vpk([(f'maps/m{i}.bsp', b'', b'x' * 1024) for i in range(100)])
        tree_end = 12 + struct.unpack_from('<I', data, 8)[0]
        data = bytearray(data[:tree_end + 1024])
        for offset in offsets.values():
            struct.pack_into('<I', data, offset + 8, 0)
        self.assertLess(len(data), 8192)
        with self.assertRaisesRegex(ValueError, '资源总大小'):
            inspect_vpk(self.source(data), allow_repair=True, max_content_bytes=8192)

    def test_v2_block_hash_is_checked_even_when_overall_hashes_match(self):
        data, _ = payload_vpk([('addoninfo.txt', b'', b'AddonInfo {}')], version=2)
        tree_size, body_size = struct.unpack_from('<II', data, 8)
        tree, body = data[28:28 + tree_size], data[28 + tree_size:28 + tree_size + body_size]
        for digest in (hashlib.md5(body).digest(), b'\xff' * 16):
            block = struct.pack('<III16s', 0x7fff, 0, body_size, digest)
            header = struct.pack('<7I', 0x55aa1234, 2, tree_size, body_size, len(block), 48, 0)
            prefix = header + tree + body + block
            hashes = hashlib.md5(tree).digest() + hashlib.md5(block).digest()
            candidate = prefix + hashes + hashlib.md5(prefix + hashes).digest()
            if digest == b'\xff' * 16:
                with self.assertRaisesRegex(ValueError, '分块校验和'):
                    validate_vpk(self.source(candidate), main.RULES_FILE)
            else:
                self.assertTrue(validate_vpk(self.source(candidate), main.RULES_FILE).ok)

    def test_sftp_invalid_overwrite_is_not_reported_active(self):
        path = Path(main.UPLOAD_DIR) / 'sftp.vpk'
        path.write_bytes(publication.map_bytes())
        now = main.time.time()
        os.utime(path, (now - 120, now - 120))
        self.assertEqual(main.sync_sftp_uploads()['imported'], 1)
        # SFTP 现在也会无损修复缺失终止符；真正损坏的内容仍须拒绝并保留原件。
        path.write_bytes(publication.map_bytes().replace(b'VBSP', b'FAIL'))
        os.utime(path, (now + 3, now + 3))
        with self.assertLogs(main.logger, level='WARNING'):
            self.assertEqual(main.sync_sftp_uploads(now_ts=now + 120)['errors'], 1)
        with SessionLocal() as db:
            row = db.query(Upload).one()
            self.assertEqual(row.status, 'invalid')
            self.assertFalse(row.vpk_valid)
        self.assertTrue(path.exists(), 'SFTP scan must not silently delete administrator files')

    def test_lan_preflight_does_not_reuse_legacy_corrupt_package(self):
        bad = missing_outer_terminator(publication.map_bytes())
        path = Path(main.UPLOAD_DIR) / 'legacy_server.vpk'
        path.write_bytes(bad)
        digest = hashlib.sha256(bad).hexdigest()
        with SessionLocal() as db:
            db.add(Upload(original_name='legacy.vpk', stored_name=path.name, sha256=digest,
                          size=len(bad), role='admin', status='active', vpk_valid=True,
                          created_at=main.now_utc()))
            db.commit()
        result = main._replication_preflight('node-a', {
            'source_node_id': 'node-a', 'lan_group': 'room-1',
            'artifacts': [{'source_upload_id': 1, 'original_name': 'legacy.vpk',
                           'stored_name': path.name, 'sha256': digest, 'size': len(bad)}],
        })
        self.assertEqual(result['status'], 'reserved')
        self.assertEqual(result['already_present'], [])
