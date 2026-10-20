"""Zero-hop neighbour table, published to the MQTT ``neighbors`` topic.

A port of the observer firmware's ``WITH_MQTT_NEIGHBORS`` feature (also in
openHop, meshcore-packet-capture and meshcore-bot) for repeaters on stock
firmware, which keep a neighbour table but cannot reach MQTT themselves.

The repeater's own ``neighbors`` CLI command is not usable for this: it
truncates its reply after ~134 characters (6-7 entries) and prints only 4-byte
key prefixes. Instead the table is rebuilt from the packets the repeater logs
over serial, using the same two sources the firmware feeds its table from
(``putNeighbour`` in ``examples/simple_repeater/MyMesh.cpp``):

* **Zero-hop repeater adverts** whose signature verifies and which are not a
  companion's "share" (transport codes ``{0, 0}``).
* **Zero-hop node-discover responses** from repeaters (CONTROL ``0x90``). Each
  names the responder by its full 32-byte key. ``discover.neighbors`` asks for
  full keys, so running it once per cycle fills the table on demand.

Both are sent zero-hop, so hearing one proves the sender is in direct radio
range; the RX SNR is how well *this* repeater hears it. Region scopes are not
collected: stock firmware has no CLI command that queries a neighbour's
scopes, so ``scopes`` is left empty.
"""
from __future__ import annotations

import json
import logging
import struct
import threading
import time
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from . import topics

if TYPE_CHECKING:
    from .state import BridgeState

logger = logging.getLogger(__name__)

PAYLOAD_TYPE_ADVERT = 0x04
PAYLOAD_TYPE_CONTROL = 0x0B
ROUTE_TRANSPORT_FLOOD = 0x00
ROUTE_TRANSPORT_DIRECT = 0x03
ADV_TYPE_REPEATER = 2
CTL_TYPE_NODE_DISCOVER_RESP = 0x90
PUB_KEY_SIZE = 32
SIGNATURE_SIZE = 64

# Firmware parity (MQTTPrefsStorage.h): 12-336 hours, default 24.
MIN_INTERVAL_HOURS = 12
MAX_INTERVAL_HOURS = 336
DEFAULT_INTERVAL_HOURS = 24
# The firmware collects discover responses for 60 s before publishing.
DEFAULT_DISCOVER_WINDOW = 60
# Rows heard longer ago than this are treated as gone (openHop's default).
DEFAULT_MAX_AGE_HOURS = 24
DEFAULT_MAX_NEIGHBORS = 50  # MAX_NEIGHBOURS in stock repeater builds
# A restart never publishes inside this window, so a crash loop cannot turn
# into a discover storm, and the radio and brokers settle first.
STARTUP_DELAY = 600


def parse_zero_hop_neighbor(raw_hex: str) -> str | None:
    """Return the full public key (upper hex) a raw packet proves is a direct
    neighbour, or None.

    Only zero-hop repeater adverts (verified, not shared) and zero-hop
    repeater discover responses qualify -- the two packets the firmware adds
    to its own neighbour table.
    """
    try:
        pkt = bytes.fromhex(raw_hex)
    except (ValueError, TypeError):
        return None
    if len(pkt) < 2:
        return None

    header = pkt[0]
    route_type = header & 0x03
    payload_type = (header >> 2) & 0x0F
    i = 1

    transport_codes: tuple[int, int] | None = None
    if route_type in (ROUTE_TRANSPORT_FLOOD, ROUTE_TRANSPORT_DIRECT):
        if len(pkt) < i + 4:
            return None
        transport_codes = struct.unpack_from('<HH', pkt, i)
        i += 4

    if len(pkt) < i + 1:
        return None
    path_len = pkt[i]
    i += 1
    if path_len & 0x3F:  # hop count: anything relayed proves nothing
        return None
    payload = pkt[i:]

    if payload_type == PAYLOAD_TYPE_CONTROL:
        if len(payload) < 6 + PUB_KEY_SIZE:
            return None  # prefix-only response: not a full key
        if payload[0] & 0xF0 != CTL_TYPE_NODE_DISCOVER_RESP:
            return None
        if payload[0] & 0x0F != ADV_TYPE_REPEATER:
            return None
        return payload[6:6 + PUB_KEY_SIZE].hex().upper()

    if payload_type == PAYLOAD_TYPE_ADVERT:
        if transport_codes == (0, 0):
            return None  # a companion's "share", not the node itself
        fixed = PUB_KEY_SIZE + 4 + SIGNATURE_SIZE
        if len(payload) < fixed + 1:
            return None
        pub_key = payload[:PUB_KEY_SIZE]
        timestamp = payload[PUB_KEY_SIZE:PUB_KEY_SIZE + 4]
        signature = payload[PUB_KEY_SIZE + 4:fixed]
        app_data = payload[fixed:]
        if app_data[0] & 0x0F != ADV_TYPE_REPEATER:
            return None
        if not _verify_advert(signature, pub_key + timestamp + app_data, pub_key):
            return None
        return pub_key.hex().upper()

    return None


def _verify_advert(signature: bytes, message: bytes, pub_key: bytes) -> bool:
    """Ed25519-verify an advert, as the firmware does before trusting it."""
    try:
        from ed25519_orlp import ed25519_verify
    except ImportError:  # pragma: no cover - a declared dependency
        return False
    try:
        return bool(ed25519_verify(signature, message, pub_key))
    except Exception:
        return False


class NeighborTable:
    """Direct neighbours heard so far: key -> (monotonic time heard, SNR)."""

    def __init__(self, max_neighbors: int = DEFAULT_MAX_NEIGHBORS) -> None:
        self._lock = threading.Lock()
        self._rows: dict[str, tuple[float, float | None]] = {}
        self.max_neighbors = max_neighbors

    def observe(self, pub_key: str, snr: float | None, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            self._rows[pub_key] = (now, snr)
            if len(self._rows) > self.max_neighbors * 2:
                # Keep memory bounded without a timer: drop the stalest half.
                keep = sorted(self._rows.items(), key=lambda kv: kv[1][0], reverse=True)
                self._rows = dict(keep[:self.max_neighbors])

    def snapshot(self, max_age_s: float, now: float | None = None) -> list[dict[str, Any]]:
        """Rows heard within max_age_s, most recent first, then strongest."""
        now = time.monotonic() if now is None else now
        with self._lock:
            rows = [(k, t, s) for k, (t, s) in self._rows.items() if now - t <= max_age_s]
        rows.sort(key=lambda r: (now - r[1], -(r[2] if r[2] is not None else -99.0), r[0]))
        out = []
        for key, heard, snr in rows[:self.max_neighbors]:
            entry: dict[str, Any] = {"pubkey": key, "heard_secs_ago": int(now - heard)}
            if snr is not None:
                entry["snr"] = snr
            entry["scopes"] = ""
            out.append(entry)
        return out

    def __len__(self) -> int:
        with self._lock:
            return len(self._rows)


def neighbors_config(state: BridgeState) -> dict[str, Any]:
    cfg = state.config.get('neighbors', {})
    return cfg if isinstance(cfg, dict) else {}


def normalize_interval_hours(value: Any) -> float:
    """Firmware parity: an out-of-range or invalid value falls back to 24, not a clamp."""
    try:
        hours = float(value)
    except (TypeError, ValueError):
        return DEFAULT_INTERVAL_HOURS
    if MIN_INTERVAL_HOURS <= hours <= MAX_INTERVAL_HOURS:
        return hours
    logger.warning(
        f"[NEIGHBORS] interval_hours={value} is outside {MIN_INTERVAL_HOURS}-"
        f"{MAX_INTERVAL_HOURS}; using {DEFAULT_INTERVAL_HOURS}")
    return DEFAULT_INTERVAL_HOURS


def opted_in_clients(state: BridgeState) -> list[dict[str, Any]]:
    """Connected brokers that opted in with ``neighbors = true``.

    Off by default per broker: some brokers reject unknown topics and drop the
    connection, so publishing here is only safe where the operator asked.
    """
    out = []
    for info in state.mqtt_clients:
        broker = topics.get_broker_config(state, info['broker_idx'])
        if broker.get('neighbors', False) and info.get('connected', False):
            out.append(info)
    return out


def neighbors_topic(state: BridgeState, broker_idx: int) -> str:
    """The broker's neighbors topic, or one derived from its packets topic.

    Existing installs have no ``neighbors`` template, so fall back to the
    packets topic with its last segment swapped -- the same derivation
    meshcore-bot uses, which lands on meshcore/{IATA}/{PUBLIC_KEY}/neighbors.
    """
    topic = topics.get_topic(state, 'neighbors', broker_idx)
    if topic:
        return topic
    packets = topics.get_topic(state, 'packets', broker_idx)
    if packets.endswith('/packets'):
        return packets[:-len('packets')] + 'neighbors'
    return ''


def build_neighbors_message(state: BridgeState, rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "origin": state.repeater_name,
        "origin_id": state.repeater_pub_key,
        "total_neighbors": len(rows),
        "queried_neighbors": 0,  # no scope queries on stock firmware
        "neighbors": rows,
    }


def publish_neighbors(state: BridgeState) -> int:
    """Publish the current table to every opted-in broker. Returns brokers sent to."""
    cfg = neighbors_config(state)
    max_age = float(cfg.get('max_age_hours', DEFAULT_MAX_AGE_HOURS)) * 3600
    rows = state.neighbor_table.snapshot(max_age)
    payload = json.dumps(build_neighbors_message(state, rows))
    sent = 0
    for info in opted_in_clients(state):
        bidx = info['broker_idx']
        name = topics.get_broker_config(state, bidx).get('name', f'broker-{bidx}')
        topic = neighbors_topic(state, bidx)
        if not topic or '{' in topic:
            logger.warning(f"[NEIGHBORS] [{name}] no usable neighbors topic, skipping")
            continue
        try:
            # QoS 0 and not retained, like the firmware: a retained table would
            # be replayed as current long after it was measured.
            if info['client'].publish(topic, payload, qos=0, retain=False):
                sent += 1
                logger.debug(f"[NEIGHBORS] [{name}] Published to {topic}")
            else:
                state.stats['publish_failures'] += 1
                logger.error(f"[NEIGHBORS] [{name}] Publish failed to {topic}")
        except Exception as e:
            state.stats['publish_failures'] += 1
            logger.error(f"[NEIGHBORS] [{name}] Publish error to {topic}: {e}")
    logger.info(f"[NEIGHBORS] Published {len(rows)} neighbour(s) to {sent} broker(s)")
    return sent


def observe_packet(state: BridgeState, raw_hex: str | None, snr: str | None) -> None:
    """Feed one received packet to the table (cheap; called per RX line)."""
    if not raw_hex or state.neighbor_table is None:
        return
    key = parse_zero_hop_neighbor(raw_hex)
    if not key or key == (state.repeater_pub_key or '').upper():
        return
    try:
        snr_val: float | None = float(snr) if snr not in (None, '') else None
    except ValueError:
        snr_val = None
    state.neighbor_table.observe(key, snr_val)
    logger.debug(f"[NEIGHBORS] direct neighbour {key[:12]} snr={snr_val}")


def run_cycle(state: BridgeState) -> int:
    """One cycle: send discover.neighbors, collect replies, publish."""
    cfg = neighbors_config(state)
    if cfg.get('discover', True) and state.device:
        ok, reply = state.device.execute_command('discover.neighbors', timeout=5)
        if not ok or 'unknown' in reply.lower() or reply.lower().startswith('err'):
            logger.warning(f"[NEIGHBORS] discover.neighbors not accepted ({reply!r}); "
                           "publishing from overheard packets only")
        else:
            window = float(cfg.get('discover_window', DEFAULT_DISCOVER_WINDOW))
            deadline = time.monotonic() + window
            while time.monotonic() < deadline and not state.should_exit:
                time.sleep(1)
    if state.should_exit:
        return 0
    return publish_neighbors(state)


def neighbors_loop(state: BridgeState) -> None:
    """Background thread: one cycle every interval_hours, or on request.

    ``state.neighbors_now`` (set by SIGUSR1) runs a cycle immediately.
    """
    cfg = neighbors_config(state)
    interval = normalize_interval_hours(cfg.get('interval_hours', DEFAULT_INTERVAL_HOURS)) * 3600
    delay = float(cfg.get('startup_delay', STARTUP_DELAY))
    logger.info(f"[NEIGHBORS] Enabled: every {interval / 3600:.0f}h, first in {delay:.0f}s; "
                f"{len(opted_in_brokers(state))} broker(s) opted in")
    next_run = time.monotonic() + delay
    while not state.should_exit:
        if state.neighbors_now.is_set() or time.monotonic() >= next_run:
            state.neighbors_now.clear()
            try:
                run_cycle(state)
            except Exception as e:
                logger.error(f"[NEIGHBORS] cycle failed: {e}")
            next_run = time.monotonic() + interval
        state.neighbors_now.wait(timeout=5)


def opted_in_brokers(state: BridgeState) -> list[str]:
    """Names of configured brokers with ``neighbors = true`` (connected or not)."""
    return [b.get('name', f'broker-{i}') for i, b in enumerate(state.config.get('broker', []))
            if b.get('enabled', True) and b.get('neighbors', False)]
