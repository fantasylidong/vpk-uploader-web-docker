import asyncio
import hashlib
import json
import os
import tempfile
import unittest

import httpx

from app.lan_replication import (
    LanPeer,
    LanReplicationConfig,
    ReplicationArtifact,
    load_lan_replication_config,
    peer_host_is_private,
    replicate_artifacts,
)


TOKEN = "a" * 64


class LanReplicationConfigTest(unittest.TestCase):
    def test_loads_json_peers_and_filters_local_node(self):
        config = load_lan_replication_config({
            "LAN_NODE_ID": "node-a",
            "LAN_GROUP": "room-1",
            "LAN_PEER_API_TOKEN": TOKEN,
            "LAN_PEER_ALLOWED_CIDRS": "10.20.0.0/24",
            "LAN_PEERS": json.dumps([
                {"id": "node-a", "url": "http://10.20.0.11:8080"},
                {"id": "node-b", "name": "Node B", "url": "http://10.20.0.12:8080/"},
            ]),
        })

        self.assertTrue(config.enabled)
        self.assertTrue(config.receiver_enabled)
        self.assertEqual([peer.node_id for peer in config.peers], ["node-b"])
        self.assertEqual(config.peers[0].url, "http://10.20.0.12:8080")
        self.assertEqual(config.public_status()["configured_peer_count"], 1)

    def test_receiver_requires_a_strong_token_and_cidr(self):
        config = load_lan_replication_config({
            "LAN_NODE_ID": "node-a",
            "LAN_GROUP": "room-1",
            "LAN_PEER_API_TOKEN": "short",
            "LAN_PEERS": '[{"id":"node-b","url":"http://10.20.0.12:8080"}]',
        })

        self.assertFalse(config.receiver_enabled)
        self.assertFalse(config.enabled)
        self.assertGreaterEqual(config.public_status()["config_error_count"], 2)

    def test_private_peer_detection_rejects_public_literal(self):
        self.assertTrue(peer_host_is_private(LanPeer("private", "Private", "http://10.0.0.2:8080")))
        self.assertFalse(peer_host_is_private(LanPeer("public", "Public", "https://8.8.8.8")))


class LanReplicationClientTest(unittest.TestCase):
    def _config(self) -> LanReplicationConfig:
        return LanReplicationConfig(
            node_id="node-a",
            group="room-1",
            token=TOKEN,
            allowed_cidrs="10.20.0.0/24",
            peers=(LanPeer("node-b", "Node B", "http://10.20.0.12:8080"),),
            disk_reserve_bytes=0,
        )

    def test_full_replication_protocol(self):
        calls = []

        async def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            self.assertEqual(request.headers["authorization"], f"Bearer {TOKEN}")
            self.assertEqual(request.headers["x-lan-group"], "room-1")
            if request.url.path.endswith("/capabilities"):
                return httpx.Response(200, json={
                    "protocol_version": 1,
                    "node_id": "node-b",
                    "lan_group": "room-1",
                })
            if request.url.path.endswith("/preflight"):
                payload = json.loads((await request.aread()).decode())
                return httpx.Response(200, json={
                    "status": "reserved",
                    "reservation_id": "1" * 48,
                    "accepted": payload["artifacts"],
                    "already_present": [],
                    "storage": {"available_bytes": 10_000},
                })
            if request.url.path.endswith("/uploads"):
                body = await request.aread()
                self.assertIn(b"map_server.vpk", body)
                self.assertIn(b"map-bytes", body)
                return httpx.Response(200, json={
                    "status": "stored",
                    "upload": {"id": 8, "original_name": "map.vpk"},
                })
            if request.url.path.endswith("/complete"):
                return httpx.Response(200, json={"status": "completed"})
            return httpx.Response(404)

        with tempfile.NamedTemporaryFile(suffix=".vpk", delete=False) as handle:
            handle.write(b"map-bytes")
            path = handle.name
        try:
            artifact = ReplicationArtifact(
                upload_id=7,
                original_name="map.vpk",
                stored_name="map_server.vpk",
                path=path,
                size=9,
                sha256=hashlib.sha256(b"map-bytes").hexdigest(),
            )
            result = asyncio.run(replicate_artifacts(
                self._config(),
                [artifact],
                transport=httpx.MockTransport(handler),
            ))
        finally:
            os.unlink(path)

        self.assertTrue(result["complete"])
        self.assertEqual(result["completed_peer_count"], 1)
        self.assertEqual(result["peers"][0]["status"], "completed")
        self.assertEqual(calls, [
            "/api/lan/replication/capabilities",
            "/api/lan/replication/preflight",
            "/api/lan/replication/uploads",
            "/api/lan/replication/reservations/" + "1" * 48 + "/complete",
        ])

    def test_capacity_shortage_skips_transfer(self):
        calls = []

        async def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            if request.url.path.endswith("/capabilities"):
                return httpx.Response(200, json={
                    "protocol_version": 1,
                    "node_id": "node-b",
                    "lan_group": "room-1",
                })
            return httpx.Response(200, json={
                "status": "insufficient_capacity",
                "detail": "容量不足",
                "required_bytes": 9,
                "already_present": [],
                "storage": {"available_bytes": 3},
            })

        with tempfile.NamedTemporaryFile(suffix=".vpk", delete=False) as handle:
            handle.write(b"map-bytes")
            path = handle.name
        try:
            artifact = ReplicationArtifact(
                upload_id=7,
                original_name="map.vpk",
                stored_name="map_server.vpk",
                path=path,
                size=9,
                sha256=hashlib.sha256(b"map-bytes").hexdigest(),
            )
            result = asyncio.run(replicate_artifacts(
                self._config(),
                [artifact],
                transport=httpx.MockTransport(handler),
            ))
        finally:
            os.unlink(path)

        self.assertFalse(result["complete"])
        self.assertEqual(result["skipped_peer_count"], 1)
        self.assertEqual(result["peers"][0]["status"], "skipped_capacity")
        self.assertEqual(calls, [
            "/api/lan/replication/capabilities",
            "/api/lan/replication/preflight",
        ])

    def test_incomplete_security_config_is_not_reported_as_complete(self):
        config = LanReplicationConfig(
            node_id="node-a",
            group="room-1",
            token="short",
            allowed_cidrs="",
            peers=(LanPeer("node-b", "Node B", "http://10.20.0.12:8080"),),
            errors=("LAN_PEER_API_TOKEN 至少需要 32 个字符", "缺少 LAN_PEER_ALLOWED_CIDRS"),
        )
        with tempfile.NamedTemporaryFile(suffix=".vpk", delete=False) as handle:
            handle.write(b"map-bytes")
            path = handle.name
        try:
            result = asyncio.run(replicate_artifacts(config, [ReplicationArtifact(
                upload_id=7,
                original_name="map.vpk",
                stored_name="map_server.vpk",
                path=path,
                size=9,
                sha256=hashlib.sha256(b"map-bytes").hexdigest(),
            )]))
        finally:
            os.unlink(path)

        self.assertFalse(result["complete"])
        self.assertEqual(result["failed_peer_count"], 1)
        self.assertEqual(result["peers"][0]["status"], "configuration_error")


if __name__ == "__main__":
    unittest.main()
