"""Tests for the zero-hop neighbour table and its MQTT publication."""
from __future__ import annotations

import json
import os
import struct

from ed25519_orlp import ed25519_create_keypair, ed25519_sign

from bridge import neighbors
from bridge.message_parser import parse_and_publish
from tests.fakes import FakeBrokerClient, FakeSerialConnection, make_config, make_test_state

ROUTE_TRANSPORT_FLOOD, ROUTE_FLOOD, ROUTE_DIRECT = 0, 1, 2


def _keypair() -> tuple[bytes, bytes]:
    pub, prv, _seed = ed25519_create_keypair(os.urandom(32))
    return pub, prv


def advert_hex(pub: bytes, prv: bytes, *, node_type: int = 2, hops: int = 0,
               route: int = ROUTE_FLOOD, transport: tuple[int, int] | None = None,
               tamper: bool = False) -> str:
    """A real, signed advert packet in on-air layout."""
    ts = struct.pack('<I', 1_790_000_000)
    app_data = bytes([0x80 | node_type]) + b'Test RPT'
    sig = ed25519_sign(pub + ts + app_data, pub, prv)
    if tamper:
        app_data = bytes([0x80 | node_type]) + b'Evil RPT'
    header = bytes([route | (0x04 << 2)])
    tc = struct.pack('<HH', *transport) if transport is not None else b''
    path = bytes([hops]) + b'\x11' * hops
    return (header + tc + path + pub + ts + sig + app_data).hex().upper()


def discover_resp_hex(pub: bytes, *, node_type: int = 2, hops: int = 0, prefix_only: bool = False) -> str:
    """A node-discover response (CONTROL 0x90 | node type) in on-air layout."""
    header = bytes([ROUTE_DIRECT | (0x0B << 2)])
    body = bytes([0x90 | node_type, 0x28]) + struct.pack('<I', 0xDEADBEEF)
    body += pub[:8] if prefix_only else pub
    path = bytes([hops]) + b'\x22' * hops
    return (header + path + body).hex().upper()


class TestParseZeroHopNeighbor:
    def test_zero_hop_repeater_advert(self):
        pub, prv = _keypair()
        assert neighbors.parse_zero_hop_neighbor(advert_hex(pub, prv)) == pub.hex().upper()

    def test_transport_flood_advert_with_region_codes(self):
        pub, prv = _keypair()
        raw = advert_hex(pub, prv, route=ROUTE_TRANSPORT_FLOOD, transport=(0x1234, 0))
        assert neighbors.parse_zero_hop_neighbor(raw) == pub.hex().upper()

    def test_shared_advert_is_not_a_neighbour(self):
        # Transport codes {0, 0} = a companion's "share": the node isn't in range.
        pub, prv = _keypair()
        raw = advert_hex(pub, prv, route=ROUTE_TRANSPORT_FLOOD, transport=(0, 0))
        assert neighbors.parse_zero_hop_neighbor(raw) is None

    def test_relayed_advert_is_not_a_neighbour(self):
        pub, prv = _keypair()
        assert neighbors.parse_zero_hop_neighbor(advert_hex(pub, prv, hops=2)) is None

    def test_companion_advert_is_ignored(self):
        pub, prv = _keypair()
        assert neighbors.parse_zero_hop_neighbor(advert_hex(pub, prv, node_type=1)) is None

    def test_bad_signature_is_rejected(self):
        pub, prv = _keypair()
        assert neighbors.parse_zero_hop_neighbor(advert_hex(pub, prv, tamper=True)) is None

    def test_discover_response(self):
        pub, _ = _keypair()
        assert neighbors.parse_zero_hop_neighbor(discover_resp_hex(pub)) == pub.hex().upper()

    def test_prefix_only_discover_response_is_ignored(self):
        pub, _ = _keypair()
        assert neighbors.parse_zero_hop_neighbor(discover_resp_hex(pub, prefix_only=True)) is None

    def test_relayed_discover_response_is_ignored(self):
        pub, _ = _keypair()
        assert neighbors.parse_zero_hop_neighbor(discover_resp_hex(pub, hops=1)) is None

    def test_junk(self):
        for raw in ("", "ZZ", "11", "1100", None):
            assert neighbors.parse_zero_hop_neighbor(raw) is None


class TestNeighborTable:
    def test_snapshot_orders_recent_then_strong_and_ages_out(self):
        t = neighbors.NeighborTable(max_neighbors=10)
        t.observe("A" * 64, -5.0, now=100.0)
        t.observe("B" * 64, 8.0, now=100.0)
        t.observe("C" * 64, 1.0, now=150.0)
        t.observe("D" * 64, 1.0, now=0.0)
        rows = t.snapshot(max_age_s=120, now=160.0)
        assert [r["pubkey"][0] for r in rows] == ["C", "B", "A"]
        assert rows[0]["heard_secs_ago"] == 10
        assert rows[1]["snr"] == 8.0

    def test_bounded(self):
        t = neighbors.NeighborTable(max_neighbors=3)
        for i in range(20):
            t.observe(f"{i:064X}", 0.0, now=float(i))
        assert len(t) <= 6
        assert len(t.snapshot(1e9, now=20.0)) == 3


def _state(*, enabled=True, broker_opt_in=True, packets_topic='meshcore/{IATA}/{PUBLIC_KEY}/packets'):
    config = make_config(neighbors={'enabled': enabled, 'interval_hours': 24, 'discover_window': 0})
    config['topics']['packets'] = packets_topic
    config['broker'][0]['neighbors'] = broker_opt_in
    broker = FakeBrokerClient()
    broker._connected = True
    state = make_test_state(
        config=config,
        broker_clients=[{"client": broker, "broker_idx": 0, "connected": True}],
        repeater_name="TestNode",
        repeater_pub_key="AA" * 32,
    )
    return state, broker


def _feed(state, raw_hex: str, snr: int = 6) -> None:
    parse_and_publish(state, f"12:34:56 - 1/15/2025 U RAW: {raw_hex}")
    parse_and_publish(state, f"12:34:56 - 1/15/2025 U: RX, len={len(raw_hex) // 2} "
                             f"(type=4, route=F, payload_len=0) SNR={snr} RSSI=-90 score=100")


class TestParserHook:
    def test_rx_packets_fill_the_table(self):
        state, _ = _state()
        pub, prv = _keypair()
        pub2, _ = _keypair()
        _feed(state, advert_hex(pub, prv), snr=7)
        _feed(state, discover_resp_hex(pub2), snr=-3)
        _feed(state, advert_hex(pub, prv, hops=3))
        rows = state.neighbor_table.snapshot(3600)
        assert {r["pubkey"] for r in rows} == {pub.hex().upper(), pub2.hex().upper()}
        assert {r["snr"] for r in rows} == {7.0, -3.0}

    def test_own_key_is_never_a_neighbour(self):
        state, _ = _state()
        state.repeater_pub_key = None
        pub, prv = _keypair()
        state.repeater_pub_key = pub.hex().upper()
        _feed(state, advert_hex(pub, prv))
        assert len(state.neighbor_table) == 0

    def test_disabled_has_no_table(self):
        state, _ = _state(enabled=False)
        pub, prv = _keypair()
        _feed(state, advert_hex(pub, prv))
        assert state.neighbor_table is None


class TestPublish:
    def test_publishes_firmware_shaped_payload_to_opted_in_broker(self):
        state, broker = _state()
        pub, _ = _keypair()
        _feed(state, discover_resp_hex(pub), snr=5)
        broker.published.clear()
        assert neighbors.publish_neighbors(state) == 1
        topic, payload, qos, retain = broker.published[0]
        assert topic == "meshcore/TST/" + "AA" * 32 + "/neighbors"
        assert (qos, retain) == (0, False)
        msg = json.loads(payload)
        assert msg["origin_id"] == "AA" * 32
        assert msg["total_neighbors"] == 1
        assert msg["neighbors"][0] == {"pubkey": pub.hex().upper(), "heard_secs_ago": 0, "snr": 5.0, "scopes": ""}

    def test_broker_not_opted_in_gets_nothing(self):
        state, broker = _state(broker_opt_in=False)
        assert neighbors.publish_neighbors(state) == 0
        assert broker.published == []

    def test_explicit_topic_template_wins(self):
        state, broker = _state()
        state.config['broker'][0]['topics'] = {'neighbors': 'custom/{IATA}/{PUBLIC_KEY}/nbr'}
        neighbors.publish_neighbors(state)
        assert broker.published[0][0] == "custom/TST/" + "AA" * 32 + "/nbr"

    def test_no_packets_suffix_and_no_template_is_skipped(self):
        state, broker = _state(packets_topic='flat/{PUBLIC_KEY}')
        assert neighbors.publish_neighbors(state) == 0


class TestCycle:
    def test_cycle_sends_discover_then_publishes(self):
        state, broker = _state()
        state.device = FakeSerialConnection(command_responses={'discover.neighbors': (True, "OK - Discover sent")})
        assert neighbors.run_cycle(state) == 1
        assert state.device.commands_executed == ['discover.neighbors']

    def test_old_firmware_still_publishes_overheard(self):
        state, broker = _state()
        state.device = FakeSerialConnection(command_responses={'discover.neighbors': (True, "Unknown command")})
        pub, prv = _keypair()
        _feed(state, advert_hex(pub, prv))
        broker.published.clear()
        assert neighbors.run_cycle(state) == 1
        assert json.loads(broker.published[0][1])["total_neighbors"] == 1

    def test_discover_can_be_turned_off(self):
        state, broker = _state()
        state.config['neighbors']['discover'] = False
        state.device = FakeSerialConnection()
        neighbors.run_cycle(state)
        assert state.device.commands_executed == []


class TestInterval:
    def test_firmware_band(self):
        assert neighbors.normalize_interval_hours(12) == 12
        assert neighbors.normalize_interval_hours(336) == 336
        assert neighbors.normalize_interval_hours(6) == 24
        assert neighbors.normalize_interval_hours(1000) == 24
        assert neighbors.normalize_interval_hours("x") == 24
