import json
import os
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

import tests._bootstrap  # noqa: E402,F401  必须先于 app.main 导入，只为设置环境

from app import main  # noqa: E402
from app.db import SessionLocal, Upload, WorkshopJob  # noqa: E402
from app.steam_workshop import WorkshopError, WorkshopItemDetails  # noqa: E402
from app.vpk_tools import build_vpk_from_dir  # noqa: E402

ITEM_ID = "2547462987"
OTHER_ITEM_ID = "1234567890"


def details_for(item_id: str, **overrides) -> WorkshopItemDetails:
    fields = {
        "published_file_id": item_id,
        "title": "测试地图",
        "file_size": 0,
        "consumer_app_id": 550,
        "filename": f"{item_id}.vpk",
        "file_url": "",
        "banned": False,
        "ban_reason": "",
        "preview_url": "",
    }
    fields.update(overrides)
    return WorkshopItemDetails(**fields)


class FakeWorkshopApi:
    """替掉真实的 Steam Web API，记录调用并按预设返回。"""

    def __init__(self, details=None, collections=None, details_error=None):
        self.details = details or {}
        self.collections = collections or {}
        self.details_error = details_error
        self.expanded: list[str] = []

    def get_details(self, published_file_ids):
        if self.details_error is not None:
            raise self.details_error
        return {item_id: self.details[item_id] for item_id in published_file_ids if item_id in self.details}

    def expand_collection(self, collection_id, depth=0):
        self.expanded.append(collection_id)
        result = self.collections.get(collection_id)
        if isinstance(result, Exception):
            raise result
        return result or []


def make_vpk(dest_path: str) -> None:
    work = tempfile.mkdtemp(prefix="workshop-vpk-src-")
    try:
        os.makedirs(os.path.join(work, "maps"))
        with open(os.path.join(work, "addoninfo.txt"), "w", encoding="utf-8") as handle:
            handle.write('"AddonInfo"\n{\n\t"addontitle"\t"测试地图"\n}\n')
        with open(os.path.join(work, "maps", "test_map.bsp"), "wb") as handle:
            handle.write(b"VBSP" + b"\0" * 4096)
        build_vpk_from_dir(work, dest_path)
    finally:
        shutil.rmtree(work, ignore_errors=True)


class WorkshopJobTestCase(unittest.TestCase):
    def setUp(self):
        os.makedirs(main.UPLOAD_DIR, exist_ok=True)
        os.makedirs(main.TMP_DIR, exist_ok=True)
        db = SessionLocal()
        try:
            db.query(WorkshopJob).delete()
            db.query(Upload).delete()
            db.query(main.AppSetting).delete()
            db.commit()
        finally:
            db.close()
        for name in os.listdir(main.UPLOAD_DIR):
            main._remove_file_quietly(os.path.join(main.UPLOAD_DIR, name))

    def create_job(self, ids=(), collections=(), ttl_hours=None, role=None) -> str:
        parsed = {"ids": list(ids), "collections": list(collections), "ttl_hours": ttl_hours}
        if role is not None:
            parsed["role"] = role
        payload = main._create_workshop_job(parsed, "10.0.0.9")
        return payload["job_id"]

    def load_job(self, job_id: str) -> dict:
        db = SessionLocal()
        try:
            return main._workshop_job_payload(db.get(WorkshopJob, job_id))
        finally:
            db.close()

    def stage_real_vpk(self, workshop_id, details, upload_max_mb):
        dest = os.path.join(main.TMP_DIR, f"workshop_{workshop_id}_staged.vpk")
        os.makedirs(main.TMP_DIR, exist_ok=True)
        make_vpk(dest)
        return [dest], "steamcmd"


class RunWorkshopJobTest(WorkshopJobTestCase):
    def test_downloaded_item_becomes_a_server_vpk_upload(self):
        job_id = self.create_job(ids=[ITEM_ID])
        api = FakeWorkshopApi(details={ITEM_ID: details_for(ITEM_ID)})

        with patch.object(main, "WORKSHOP_API", api), \
             patch.object(main, "_workshop_stage_downloads", self.stage_real_vpk):
            upload_ids = main._run_workshop_job(job_id)

        self.assertEqual(len(upload_ids), 1)
        job = self.load_job(job_id)
        self.assertEqual(job["status"], "succeeded")
        self.assertEqual(job["item_total"], 1)
        self.assertEqual(job["upload_count"], 1)
        item = job["items"][0]
        self.assertEqual(item["state"], "succeeded")
        self.assertEqual(item["title"], "测试地图")
        self.assertEqual(item["download_source"], "steamcmd")

        db = SessionLocal()
        try:
            upload = db.get(Upload, upload_ids[0])
            self.assertEqual(upload.status, "active")
            # 默认按普通用户入库：保存时间跟节点后台的「普通用户保存时间」走（缺省 24 小时）。
            self.assertEqual(upload.role, "guest")
            expires_at = main._as_aware_utc(upload.expires_at)
            self.assertIsNotNone(expires_at)
            remaining = (expires_at - main.now_utc()).total_seconds()
            self.assertTrue(23 * 3600 < remaining <= 24 * 3600)
            self.assertEqual(upload.uploader_ip, f"workshop:{ITEM_ID}")
            self.assertTrue(upload.original_name.endswith(f"_{ITEM_ID}.vpk"))
            self.assertTrue(os.path.isfile(os.path.join(main.UPLOAD_DIR, upload.stored_name)))
            report = json.loads(upload.vpk_report)
            self.assertEqual(report["upload_source"]["source"], "steam_workshop")
            self.assertEqual(report["upload_source"]["workshop_id"], ITEM_ID)
        finally:
            db.close()

    def run_single(self, job_id: str) -> Upload:
        api = FakeWorkshopApi(details={ITEM_ID: details_for(ITEM_ID)})
        with patch.object(main, "WORKSHOP_API", api), \
             patch.object(main, "_workshop_stage_downloads", self.stage_real_vpk):
            upload_ids = main._run_workshop_job(job_id)
        db = SessionLocal()
        try:
            upload = db.get(Upload, upload_ids[0])
            db.expunge(upload)
            return upload
        finally:
            db.close()

    def test_admin_ttl_hours_sets_expiry(self):
        upload = self.run_single(self.create_job(ids=[ITEM_ID], ttl_hours=6, role="admin"))
        self.assertEqual(upload.role, "admin")
        remaining = (main._as_aware_utc(upload.expires_at) - main.now_utc()).total_seconds()
        self.assertTrue(5 * 3600 < remaining <= 6 * 3600)

    def test_admin_without_ttl_is_permanent(self):
        upload = self.run_single(self.create_job(ids=[ITEM_ID], role="admin"))
        self.assertIsNone(upload.expires_at)

    def test_guest_follows_the_node_guest_ttl_setting(self):
        main.set_guest_ttl_hours(0)
        upload = self.run_single(self.create_job(ids=[ITEM_ID]))
        self.assertEqual(upload.role, "guest")
        self.assertIsNone(upload.expires_at, "普通用户保存时间设成 0 就是永久")

    def test_collection_is_expanded_into_items(self):
        job_id = self.create_job(collections=["900000001"])
        api = FakeWorkshopApi(
            details={
                ITEM_ID: details_for(ITEM_ID),
                OTHER_ITEM_ID: details_for(OTHER_ITEM_ID, title="第二张图"),
            },
            collections={"900000001": [ITEM_ID, OTHER_ITEM_ID]},
        )

        with patch.object(main, "WORKSHOP_API", api), \
             patch.object(main, "_workshop_stage_downloads", self.stage_real_vpk):
            upload_ids = main._run_workshop_job(job_id)

        self.assertEqual(api.expanded, ["900000001"])
        self.assertEqual(len(upload_ids), 2)
        job = self.load_job(job_id)
        self.assertEqual(job["status"], "succeeded")
        self.assertEqual([item["origin"] for item in job["items"]], ["collection:900000001"] * 2)

    def test_download_failure_marks_item_failed(self):
        job_id = self.create_job(ids=[ITEM_ID])
        api = FakeWorkshopApi(details={ITEM_ID: details_for(ITEM_ID)})

        def boom(workshop_id, details, upload_max_mb):
            raise WorkshopError("steamcmd 下载失败：测试")

        with patch.object(main, "WORKSHOP_API", api), \
             patch.object(main, "_workshop_stage_downloads", boom):
            upload_ids = main._run_workshop_job(job_id)

        self.assertEqual(upload_ids, [])
        job = self.load_job(job_id)
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["items"][0]["state"], "failed")
        self.assertIn("测试", job["items"][0]["error"])

    def test_partial_job_when_only_one_item_succeeds(self):
        job_id = self.create_job(ids=[ITEM_ID, OTHER_ITEM_ID])
        api = FakeWorkshopApi(details={
            ITEM_ID: details_for(ITEM_ID),
            OTHER_ITEM_ID: details_for(OTHER_ITEM_ID),
        })

        def stage(workshop_id, details, upload_max_mb):
            if workshop_id == OTHER_ITEM_ID:
                raise WorkshopError("下载失败")
            return self.stage_real_vpk(workshop_id, details, upload_max_mb)

        with patch.object(main, "WORKSHOP_API", api), \
             patch.object(main, "_workshop_stage_downloads", stage):
            upload_ids = main._run_workshop_job(job_id)

        self.assertEqual(len(upload_ids), 1)
        self.assertEqual(self.load_job(job_id)["status"], "partial")

    def test_empty_collection_fails_job_with_note(self):
        job_id = self.create_job(collections=["900000001"])
        api = FakeWorkshopApi(collections={"900000001": []})

        with patch.object(main, "WORKSHOP_API", api):
            self.assertEqual(main._run_workshop_job(job_id), [])

        job = self.load_job(job_id)
        self.assertEqual(job["status"], "failed")
        self.assertIn("没有读到成员", job["error"])

    def test_details_lookup_failure_does_not_block_download(self):
        job_id = self.create_job(ids=[ITEM_ID])
        api = FakeWorkshopApi(details_error=WorkshopError("Steam Web API 超时"))

        with patch.object(main, "WORKSHOP_API", api), \
             patch.object(main, "_workshop_stage_downloads", self.stage_real_vpk):
            upload_ids = main._run_workshop_job(job_id)

        self.assertEqual(len(upload_ids), 1)
        job = self.load_job(job_id)
        self.assertEqual(job["status"], "succeeded")
        self.assertIn("读取物品信息失败", job["error"])
        # 没有标题时用 workshop_<id> 兜底
        self.assertTrue(job["items"][0]["uploads"][0]["original_name"].startswith("workshop_"))

    def test_duplicate_ids_are_processed_once(self):
        job_id = self.create_job(ids=[ITEM_ID, ITEM_ID])
        api = FakeWorkshopApi(details={ITEM_ID: details_for(ITEM_ID)})

        with patch.object(main, "WORKSHOP_API", api), \
             patch.object(main, "_workshop_stage_downloads", self.stage_real_vpk):
            main._run_workshop_job(job_id)

        self.assertEqual(self.load_job(job_id)["item_total"], 1)


class StageDownloadGuardTest(WorkshopJobTestCase):
    def test_banned_item_is_rejected(self):
        details = details_for(ITEM_ID, banned=True, ban_reason="侵权")
        with self.assertRaises(WorkshopError) as ctx:
            main._workshop_stage_downloads(ITEM_ID, details, 1024)
        self.assertIn("侵权", str(ctx.exception))

    def test_foreign_appid_is_rejected(self):
        details = details_for(ITEM_ID, consumer_app_id=730)
        with self.assertRaises(WorkshopError) as ctx:
            main._workshop_stage_downloads(ITEM_ID, details, 1024)
        self.assertIn("730", str(ctx.exception))

    def test_oversized_item_is_rejected_before_download(self):
        details = details_for(
            ITEM_ID,
            filename="map.vpk",
            file_url="https://cdn.steamusercontent.com/ugc/1/A/",
            preview_url="https://images.steamusercontent.com/ugc/2/B/",
            file_size=200 * 1024 * 1024,
        )
        with self.assertRaises(WorkshopError) as ctx:
            main._workshop_stage_downloads(ITEM_ID, details, 10)
        self.assertIn("超过单文件上限", str(ctx.exception))

    def test_preview_only_item_skips_direct_download(self):
        # file_url 退化成预览图时不能照着下，必须交给 steamcmd。
        preview = "https://images.steamusercontent.com/ugc/9/AB/"
        details = details_for(
            ITEM_ID,
            filename="cover.png",
            file_url=preview,
            preview_url=preview,
            file_size=145148,
        )
        with patch.object(main, "download_direct") as direct, \
             patch.object(main.WORKSHOP_STEAMCMD, "download", side_effect=WorkshopError("无 steamcmd")):
            with self.assertRaises(WorkshopError):
                main._workshop_stage_downloads(ITEM_ID, details, 1024)
        direct.assert_not_called()

    def test_direct_download_returning_non_vpk_falls_back_to_steamcmd(self):
        details = details_for(
            ITEM_ID,
            filename="map.vpk",
            file_url="https://cdn.steamusercontent.com/ugc/1/A/",
            preview_url="https://images.steamusercontent.com/ugc/2/B/",
            file_size=1024,
        )

        def fake_direct(item_details, dest_path, max_bytes, timeout_seconds):
            with open(dest_path, "wb") as out:
                out.write(b"\x89PNG\r\n\x1a\n")
            return 8

        content_dir = os.path.join(main.TMP_DIR, "fake-content")
        os.makedirs(content_dir, exist_ok=True)
        self.addCleanup(shutil.rmtree, content_dir, True)
        make_vpk(os.path.join(content_dir, f"{ITEM_ID}.vpk"))

        with patch.object(main.SteamCmdRunner, "available", True), \
             patch.object(main, "download_direct", side_effect=fake_direct), \
             patch.object(main.WORKSHOP_STEAMCMD, "download", return_value=content_dir), \
             patch.object(main.WORKSHOP_STEAMCMD, "cleanup"):
            staged, source = main._workshop_stage_downloads(ITEM_ID, details, 1024)

        self.addCleanup(main._remove_file_quietly, staged[0])
        self.assertEqual(source, "steamcmd")
        self.assertEqual(len(staged), 1)

    def test_capacity_shortage_is_rejected_before_download(self):
        details = details_for(
            ITEM_ID,
            filename="map.vpk",
            file_url="https://cdn.steamusercontent.com/ugc/1/A/",
            preview_url="https://images.steamusercontent.com/ugc/2/B/",
            file_size=5 * 1024 * 1024,
        )
        with patch.object(main, "_workshop_available_bytes", return_value=1024), \
             self.assertRaises(WorkshopError) as ctx:
            main._workshop_stage_downloads(ITEM_ID, details, 1024)
        self.assertIn("可用容量不足", str(ctx.exception))


class StagedFileCleanupTest(WorkshopJobTestCase):
    def test_stale_staged_vpk_is_removed(self):
        stale = os.path.join(main.TMP_DIR, "workshop_2547462987_abcd.vpk")
        fresh = os.path.join(main.TMP_DIR, "workshop_1234567890_efgh.vpk")
        keep = os.path.join(main.TMP_DIR, "something-else.vpk")
        for path in (stale, fresh, keep):
            with open(path, "wb") as handle:
                handle.write(b"x")
        old_ts = time.time() - (main.WORK_MAX_AGE_MIN * 60 + 120)
        os.utime(stale, (old_ts, old_ts))
        os.utime(keep, (old_ts, old_ts))

        main.cleanup_tmp_and_work()

        self.assertFalse(os.path.exists(stale))
        self.assertTrue(os.path.exists(fresh))
        self.assertTrue(os.path.exists(keep))
        for path in (fresh, keep):
            main._remove_file_quietly(path)


class WorkshopFilenameTest(unittest.TestCase):
    def test_sanitizes_separators_and_keeps_chinese(self):
        details = details_for(ITEM_ID, title="死亡/中心: 第一章")
        self.assertEqual(
            main._workshop_vpk_filename(details, ITEM_ID, 1, 1),
            f"死亡_中心_ 第一章_{ITEM_ID}.vpk",
        )

    def test_indexes_multiple_vpks_from_one_item(self):
        details = details_for(ITEM_ID, title="地图")
        self.assertEqual(
            main._workshop_vpk_filename(details, ITEM_ID, 2, 3),
            f"地图_{ITEM_ID}_2.vpk",
        )

    def test_missing_details_falls_back_to_id(self):
        self.assertEqual(
            main._workshop_vpk_filename(None, ITEM_ID, 1, 1),
            f"workshop_{ITEM_ID}_{ITEM_ID}.vpk",
        )

    def test_blank_title_falls_back_to_id(self):
        details = details_for(ITEM_ID, title="...")
        self.assertEqual(
            main._workshop_vpk_filename(details, ITEM_ID, 1, 1),
            f"workshop_{ITEM_ID}_{ITEM_ID}.vpk",
        )


class WorkshopRequestPayloadTest(unittest.TestCase):
    def test_accepts_items_and_collections(self):
        parsed = main._workshop_request_payload({
            "items": f"{ITEM_ID}\nhttps://steamcommunity.com/sharedfiles/filedetails/?id={OTHER_ITEM_ID}",
            "collections": ["900000001"],
            "role": "admin",
            "ttl_hours": "12",
        })
        self.assertEqual(parsed["ids"], [ITEM_ID, OTHER_ITEM_ID])
        self.assertEqual(parsed["collections"], ["900000001"])
        self.assertEqual(parsed["ttl_hours"], 12)

    def test_rejects_empty_request(self):
        for payload in ({}, {"items": []}, "not-a-dict"):
            with self.assertRaises(main.HTTPException) as ctx:
                main._workshop_request_payload(payload)
            self.assertEqual(ctx.exception.status_code, 400)

    def test_rejects_bad_ttl(self):
        with self.assertRaises(main.HTTPException) as ctx:
            main._workshop_request_payload({"ids": [ITEM_ID], "role": "admin", "ttl_hours": "soon"})
        self.assertEqual(ctx.exception.status_code, 400)

    def test_role_defaults_to_guest_and_ignores_caller_ttl(self):
        parsed = main._workshop_request_payload({"ids": [ITEM_ID], "ttl_hours": 9999})
        self.assertEqual(parsed["role"], "guest")
        self.assertIsNone(parsed["ttl_hours"], "普通用户的保存时间只能由节点后台决定")

    def test_admin_role_keeps_ttl(self):
        parsed = main._workshop_request_payload({"ids": [ITEM_ID], "role": "Admin", "ttl_hours": 12})
        self.assertEqual(parsed["role"], "admin")
        self.assertEqual(parsed["ttl_hours"], 12)

    def test_rejects_unknown_role(self):
        with self.assertRaises(main.HTTPException) as ctx:
            main._workshop_request_payload({"ids": [ITEM_ID], "role": "root"})
        self.assertEqual(ctx.exception.status_code, 400)


class ExtendExpiryTest(unittest.TestCase):
    """同一张图再部署一次要续期，不能因为去重就沿用快过期的旧记录。"""

    def upload(self, expires_at):
        return Upload(original_name="a.vpk", stored_name="a.vpk", role="guest", expires_at=expires_at)

    def test_later_expiry_wins(self):
        soon = main.now_utc() + main.timedelta(hours=1)
        later = main.now_utc() + main.timedelta(hours=24)
        existing = self.upload(soon)
        main._extend_expiry(existing, later)
        self.assertEqual(existing.expires_at, later)

    def test_earlier_expiry_does_not_shorten(self):
        later = main.now_utc() + main.timedelta(hours=24)
        existing = self.upload(later)
        main._extend_expiry(existing, main.now_utc() + main.timedelta(hours=1))
        self.assertEqual(existing.expires_at, later)

    def test_permanent_stays_permanent(self):
        existing = self.upload(None)
        main._extend_expiry(existing, main.now_utc() + main.timedelta(hours=1))
        self.assertIsNone(existing.expires_at)

    def test_permanent_upload_makes_existing_permanent(self):
        existing = self.upload(main.now_utc() + main.timedelta(hours=1))
        main._extend_expiry(existing, None)
        self.assertIsNone(existing.expires_at)


class WorkshopPublicStatusTest(WorkshopJobTestCase):
    def test_reports_real_steamcmd_readiness_and_guest_defaults(self):
        main.set_guest_ttl_hours(48)
        main.set_upload_max_mb(300)
        db = SessionLocal()
        try:
            with patch.object(main.WORKSHOP_STEAMCMD, "readiness", return_value=(False, "无法解析 client-download.steampowered.com")):
                status = main.workshop_public_status(db)
        finally:
            db.close()
        self.assertFalse(status["steamcmd_ready"])
        self.assertIn("client-download", status["steamcmd_error"])
        self.assertEqual(status["default_role"], "guest")
        self.assertEqual(status["upload_max_mb"], 300)
        self.assertEqual(status["guest_ttl_hours"], 48)


class WorkshopJobLifecycleTest(WorkshopJobTestCase):
    def test_queue_limit_returns_429(self):
        with patch.object(main, "WORKSHOP", main.WORKSHOP.__class__(max_queued_jobs=1)):
            self.create_job(ids=[ITEM_ID])
            with self.assertRaises(main.HTTPException) as ctx:
                self.create_job(ids=[OTHER_ITEM_ID])
        self.assertEqual(ctx.exception.status_code, 429)

    def test_restart_marks_running_jobs_failed(self):
        job_id = self.create_job(ids=[ITEM_ID])
        main._fail_orphaned_workshop_jobs()
        job = self.load_job(job_id)
        self.assertEqual(job["status"], "failed")
        self.assertIn("重启", job["error"])

    def test_expired_jobs_are_cleaned_up(self):
        job_id = self.create_job(ids=[ITEM_ID])
        main._finish_workshop_job(job_id, "succeeded")
        db = SessionLocal()
        try:
            job = db.get(WorkshopJob, job_id)
            job.created_at = main.now_utc() - main.timedelta(
                hours=main.WORKSHOP.job_retention_hours + 1
            )
            db.commit()
        finally:
            db.close()

        main._workshop_cleanup_at = 0.0
        main.cleanup_workshop_jobs()

        db = SessionLocal()
        try:
            self.assertIsNone(db.get(WorkshopJob, job_id))
        finally:
            db.close()

    def test_recent_jobs_survive_cleanup(self):
        job_id = self.create_job(ids=[ITEM_ID])
        main._finish_workshop_job(job_id, "succeeded")
        main._workshop_cleanup_at = 0.0
        main.cleanup_workshop_jobs()
        db = SessionLocal()
        try:
            self.assertIsNotNone(db.get(WorkshopJob, job_id))
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
