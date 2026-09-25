import os
import shutil
import tempfile
import unittest

from unittest.mock import patch
from urllib.parse import parse_qs

import httpx

from app.steam_workshop import (  # noqa: E402
    MAX_ITEMS_PER_JOB,
    SteamCmdRunner,
    SteamWebApiClient,
    WorkshopError,
    WorkshopItemDetails,
    collect_vpk_files,
    details_from_payload,
    direct_download_host_allowed,
    load_workshop_config,
    looks_like_vpk,
    parse_supplied_details,
    parse_workshop_id,
    parse_workshop_ids,
)

CONFIG = load_workshop_config({})


def api_client(handler) -> SteamWebApiClient:
    return SteamWebApiClient(
        CONFIG,
        client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler), timeout=5),
    )


class ParseWorkshopIdTest(unittest.TestCase):
    def test_accepts_plain_id(self):
        self.assertEqual(parse_workshop_id(" 2547462987 "), "2547462987")

    def test_accepts_shared_files_url(self):
        self.assertEqual(
            parse_workshop_id("https://steamcommunity.com/sharedfiles/filedetails/?id=123456789"),
            "123456789",
        )

    def test_accepts_workshop_url_with_extra_query(self):
        self.assertEqual(
            parse_workshop_id(
                "https://steamcommunity.com/workshop/filedetails/?id=987654321&searchtext=map"
            ),
            "987654321",
        )

    def test_accepts_url_without_scheme_and_query(self):
        self.assertEqual(
            parse_workshop_id("steamcommunity.com/sharedfiles/filedetails/123456789"),
            "123456789",
        )

    def test_rejects_foreign_host(self):
        with self.assertRaises(WorkshopError):
            parse_workshop_id("https://example.com/sharedfiles/filedetails/?id=123456789")

    def test_rejects_empty_and_non_numeric(self):
        for value in ("", "   ", "abc"):
            with self.assertRaises(WorkshopError):
                parse_workshop_id(value)


class ParseWorkshopIdsTest(unittest.TestCase):
    def test_parses_multiline_text_and_deduplicates(self):
        raw = (
            "123456789\n"
            "https://steamcommunity.com/sharedfiles/filedetails/?id=987654321\n"
            "\n"
            "123456789\n"
        )
        self.assertEqual(parse_workshop_ids(raw), ["123456789", "987654321"])

    def test_parses_list_input(self):
        self.assertEqual(
            parse_workshop_ids(["123456789", "  987654321  "]),
            ["123456789", "987654321"],
        )

    def test_none_is_empty(self):
        self.assertEqual(parse_workshop_ids(None), [])

    def test_rejects_oversized_batch(self):
        with self.assertRaises(WorkshopError):
            parse_workshop_ids([str(1000000 + index) for index in range(MAX_ITEMS_PER_JOB + 5)])

    def test_rejects_unsupported_type(self):
        with self.assertRaises(WorkshopError):
            parse_workshop_ids({"id": "123456789"})


class DirectDownloadHostTest(unittest.TestCase):
    def test_allows_steam_cdn_hosts(self):
        for url in (
            "https://cloud-3.steamusercontent.com/ugc/123/ABC/",
            "http://steamcdn-a.akamaihd.net/ugc/1/2/",
            "https://media.steamstatic.com/ugc/1/2/",
        ):
            self.assertTrue(direct_download_host_allowed(url), url)

    def test_rejects_other_hosts_and_schemes(self):
        for url in (
            "https://example.com/ugc/1",
            "https://steamusercontent.com.evil.test/ugc/1",
            "file:///etc/passwd",
            "",
        ):
            self.assertFalse(direct_download_host_allowed(url), url)


class SteamWebApiTest(unittest.TestCase):
    def test_get_details_parses_and_skips_failed_entries(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertIn("GetPublishedFileDetails", str(request.url))
            return httpx.Response(200, json={"response": {"publishedfiledetails": [
                {
                    "publishedfileid": "111111111",
                    "result": 1,
                    "title": "测试地图",
                    "file_size": "2048",
                    "consumer_app_id": 550,
                    "filename": "111111111.vpk",
                    "file_url": "https://cloud-3.steamusercontent.com/ugc/111111111/AAA/",
                    "banned": 0,
                },
                {"publishedfileid": "222222222", "result": 9},
            ]}})

        details = api_client(handler).get_details(["111111111", "222222222"])
        self.assertEqual(set(details), {"111111111"})
        item = details["111111111"]
        self.assertEqual(item.title, "测试地图")
        self.assertEqual(item.file_size, 2048)
        self.assertEqual(item.consumer_app_id, 550)
        self.assertFalse(item.banned)

    def test_get_details_without_ids_skips_request(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("should not perform a request")

        self.assertEqual(api_client(handler).get_details([]), {})

    def test_display_title_falls_back_to_id(self):
        item = WorkshopItemDetails("333333333", "", 0, 550, "", "", False, "")
        self.assertEqual(item.display_title, "workshop_333333333")

    def test_expand_collection_recurses_and_deduplicates(self):
        def handler(request: httpx.Request) -> httpx.Response:
            requested = parse_qs(request.content.decode())
            collection_id = requested["publishedfileids[0]"][0]
            children = {
                "900000001": [{"publishedfileid": "111111111", "filetype": 0},
                              {"publishedfileid": "900000002", "filetype": 2}],
                "900000002": [{"publishedfileid": "222222222", "filetype": 0},
                              {"publishedfileid": "111111111", "filetype": 0}],
            }.get(collection_id, [])
            return httpx.Response(200, json={"response": {"collectiondetails": [
                {"publishedfileid": collection_id, "result": 1, "children": children},
            ]}})

        self.assertEqual(
            api_client(handler).expand_collection("900000001"),
            ["111111111", "222222222"],
        )

    def test_expand_collection_skips_malformed_children(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"response": {"collectiondetails": [
                {"publishedfileid": "900000001", "result": 1, "children": [
                    "not-a-dict",
                    {"publishedfileid": "abc", "filetype": 0},
                    {"publishedfileid": "111111111", "filetype": 0},
                ]},
            ]}})

        self.assertEqual(api_client(handler).expand_collection("900000001"), ["111111111"])

    def test_expand_collection_returns_empty_for_plain_item(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"response": {"collectiondetails": [
                {"publishedfileid": "111111111", "result": 9},
            ]}})

        self.assertEqual(api_client(handler).expand_collection("111111111"), [])

    def test_http_error_becomes_workshop_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="boom")

        with self.assertRaises(WorkshopError):
            api_client(handler).get_details(["111111111"])


class HasLegacyVpkTest(unittest.TestCase):
    def details(self, **overrides) -> WorkshopItemDetails:
        fields = {
            "published_file_id": "111111111",
            "title": "地图",
            "file_size": 1024,
            "consumer_app_id": 550,
            "filename": "map.vpk",
            "file_url": "https://cdn.steamusercontent.com/ugc/1/A/",
            "banned": False,
            "ban_reason": "",
            "preview_url": "https://images.steamusercontent.com/ugc/2/B/",
        }
        fields.update(overrides)
        return WorkshopItemDetails(**fields)

    def test_true_for_legacy_ugc(self):
        self.assertTrue(self.details().has_legacy_vpk)

    def test_false_when_file_url_is_the_preview_image(self):
        # SteamPipe 托管的物品没有内容文件，Steam 会把预览图塞进 file_url。
        preview = "https://images.steamusercontent.com/ugc/2/B/"
        item = self.details(file_url=preview, preview_url=preview, filename="cover.png")
        self.assertFalse(item.has_legacy_vpk)

    def test_false_when_filename_is_not_a_vpk(self):
        self.assertFalse(self.details(filename="cover.png").has_legacy_vpk)

    def test_false_without_file_url(self):
        self.assertFalse(self.details(file_url="").has_legacy_vpk)


class LooksLikeVpkTest(unittest.TestCase):
    def write(self, payload: bytes) -> str:
        handle, path = tempfile.mkstemp(suffix=".vpk")
        self.addCleanup(os.remove, path)
        with os.fdopen(handle, "wb") as out:
            out.write(payload)
        return path

    def test_accepts_vpk_magic(self):
        self.assertTrue(looks_like_vpk(self.write(b"\x34\x12\xaa\x55rest")))

    def test_rejects_png_and_empty_files(self):
        self.assertFalse(looks_like_vpk(self.write(b"\x89PNG\r\n")))
        self.assertFalse(looks_like_vpk(self.write(b"")))

    def test_rejects_missing_file(self):
        self.assertFalse(looks_like_vpk("/nonexistent/path.vpk"))


class SteamCmdFailureReasonTest(unittest.TestCase):
    def runner(self) -> SteamCmdRunner:
        home = tempfile.mkdtemp(prefix="steamcmd-home-")
        self.addCleanup(shutil.rmtree, home, True)
        return SteamCmdRunner(load_workshop_config({"STEAMCMD_HOME": home}))

    def write_bootstrap_log(self, runner: SteamCmdRunner, text: str) -> None:
        log_dir = os.path.join(runner.config.steamcmd_home, "Steam", "logs")
        os.makedirs(log_dir, exist_ok=True)
        with open(os.path.join(log_dir, "bootstrap_log.txt"), "w", encoding="utf-8") as handle:
            handle.write(text)

    def test_prefers_error_line_from_stdout(self):
        runner = self.runner()
        reason = runner._failure_reason("ok\nERROR! Download item 1 failed (Failure).\n", 1)
        self.assertIn("ERROR! Download item", reason)

    def test_falls_back_to_bootstrap_log_when_stdout_is_silent(self):
        runner = self.runner()
        self.write_bootstrap_log(
            runner,
            "[2026-09-10] Checking for available update...\n"
            "[2026-09-10] Download failed: http error 0 (client-download.steampowered.com)\n",
        )
        reason = runner._failure_reason("", 1)
        self.assertIn("退出码 1", reason)
        self.assertIn("client-download.steampowered.com", reason)

    def test_plain_exit_code_when_no_log(self):
        self.assertEqual(self.runner()._failure_reason("", 3), "steamcmd 退出码 3")


class CollectVpkFilesTest(unittest.TestCase):
    def test_only_returns_vpk_files(self):
        root = tempfile.mkdtemp(prefix="workshop-content-")
        self.addCleanup(shutil.rmtree, root, True)
        os.makedirs(os.path.join(root, "nested"))
        for rel in ("a.vpk", "readme.txt", os.path.join("nested", "b.VPK")):
            with open(os.path.join(root, rel), "wb") as handle:
                handle.write(b"x")
        found = [os.path.relpath(path, root) for path in collect_vpk_files(root)]
        self.assertEqual(sorted(found), sorted(["a.vpk", os.path.join("nested", "b.VPK")]))



class SuppliedDetailsTest(unittest.TestCase):
    """上游把已经查好的直链带过来，节点就不用自己访问 Steam Web API。

    很多机房连不上 api.steampowered.com，但 UGC CDN 是通的。
    """

    GOOD = {
        "file_url": "https://cdn.steamusercontent.com/ugc/123/ABC/",
        "filename": "whit.vpk",
        "file_size": 5636096,
        "title": "Whitaker's Weapons Range",
        "consumer_app_id": 550,
    }

    def test_accepts_a_well_formed_payload(self):
        details = details_from_payload("3001153036", self.GOOD, 550)
        self.assertIsNotNone(details)
        self.assertEqual(details.published_file_id, "3001153036")
        self.assertEqual(details.file_size, 5636096)
        self.assertTrue(details.has_legacy_vpk)

    def test_rejects_a_url_outside_the_steam_download_hosts(self):
        payload = {**self.GOOD, "file_url": "https://evil.example.com/a.vpk"}
        self.assertIsNone(details_from_payload("1", payload, 550))

    def test_rejects_plain_http(self):
        payload = {**self.GOOD, "file_url": "http://cdn.steamusercontent.com/ugc/1/2/"}
        self.assertIsNone(details_from_payload("1", payload, 550))

    def test_rejects_a_non_vpk_filename(self):
        payload = {**self.GOOD, "filename": "preview.png"}
        self.assertIsNone(details_from_payload("1", payload, 550))

    def test_rejects_a_mismatched_appid(self):
        payload = {**self.GOOD, "consumer_app_id": 730}
        self.assertIsNone(details_from_payload("1", payload, 550))

    def test_missing_appid_is_allowed(self):
        payload = {k: v for k, v in self.GOOD.items() if k != "consumer_app_id"}
        self.assertIsNotNone(details_from_payload("1", payload, 550))

    def test_rejects_non_mapping(self):
        self.assertIsNone(details_from_payload("1", None, 550))
        self.assertIsNone(details_from_payload("1", "nope", 550))

    def test_parse_supplied_details_keys_by_workshop_id(self):
        parsed = parse_supplied_details({
            "https://steamcommunity.com/sharedfiles/filedetails/?id=3001153036": self.GOOD,
            "3360305524": self.GOOD,
            "not-an-id": self.GOOD,
            "42": self.GOOD,                 # 太短，不是合法工坊 ID
            "2547462987": "not a mapping",
        })
        self.assertEqual(sorted(parsed), ["3001153036", "3360305524"])

    def test_parse_supplied_details_rejects_a_non_object(self):
        with self.assertRaises(WorkshopError):
            parse_supplied_details(["1", "2"])

    def test_parse_supplied_details_tolerates_absence(self):
        self.assertEqual(parse_supplied_details(None), {})


class SteamCmdReadinessTest(unittest.TestCase):
    """镜像里有 steamcmd 不等于能用：连不上自更新服务器时它每次都会静默退出。"""

    def runner(self, prober, with_dist=True) -> SteamCmdRunner:
        home = tempfile.mkdtemp(prefix="steamcmd-home-")
        self.addCleanup(shutil.rmtree, home, True)
        dist = os.path.join(home, "dist")
        if with_dist:
            os.makedirs(dist)
        config = load_workshop_config({"STEAMCMD_HOME": os.path.join(home, "steamcmd"), "STEAMCMD_DIST": dist})
        return SteamCmdRunner(config, prober=prober)

    def test_unreachable_update_host_is_not_ready(self):
        calls = []

        def prober(host, ports, timeout):
            calls.append(host)
            return False, f"无法解析 {host}"

        runner = self.runner(prober)
        ready, reason = runner.readiness(block=True)
        self.assertFalse(ready)
        self.assertIn("client-download.steampowered.com", reason)
        # 结论会缓存，summary 频繁调用也不会反复探测。
        runner.readiness(block=True)
        runner.readiness()
        self.assertEqual(len(calls), 1)

    def test_reachable_update_host_is_ready(self):
        runner = self.runner(lambda host, ports, timeout: (True, ""))
        self.assertEqual(runner.readiness(block=True), (True, ""))

    def test_missing_binary_is_never_ready(self):
        runner = self.runner(lambda host, ports, timeout: (True, ""), with_dist=False)
        ready, reason = runner.readiness(block=True)
        self.assertFalse(ready)
        self.assertIn("没有内置 steamcmd", reason)

    def test_non_blocking_readiness_does_not_claim_ready_before_probing(self):
        started = []

        def prober(host, ports, timeout):
            started.append(host)
            return True, ""

        runner = self.runner(prober)
        with patch.object(runner, "refresh_readiness_async") as refresh:
            ready, _ = runner.readiness()
        self.assertFalse(ready)
        refresh.assert_called_once()
        self.assertEqual(started, [])

    def test_download_fails_fast_when_not_ready(self):
        runner = self.runner(lambda host, ports, timeout: (False, "连不上 client-download.steampowered.com"))
        with patch("app.steam_workshop.subprocess.run") as run, \
                self.assertRaises(WorkshopError) as ctx:
            runner.download("2547462987")
        run.assert_not_called()
        self.assertIn("steamcmd 当前不可用", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
