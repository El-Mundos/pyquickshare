from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
from collections.abc import AsyncGenerator, Callable
from typing import Any, cast

from dbus_next.aio.message_bus import MessageBus
from dbus_next.constants import BusType
from dbus_next.signature import Variant

from pyquickshare.common import from_url64, to_url64

from . import rfcomm
from .dbus.dbus import get_proxy_object
from .dbus.profile import _QuickShareProfile
from .dbus.untyped import _ReceiveAdvertisement
from .mdns.receive import EndpointInfo, parse_endpoint_info

logger = logging.getLogger(__name__)


BLEUTOOTH_QUICKSHARE_UUID = "a82efa21-ae5c-3dde-9bbc-f16da7b16c5a"
BLEUTOOTH_QUICKSHARE_RECEIVE_UUID = "0000fef3-0000-1000-8000-00805f9b34fb"
BLUETOOTH_QUICKSHARE_NEW_UUID = "00001101-0000-1000-8000-00805f9b34fb"
UUIDS = [
    BLEUTOOTH_QUICKSHARE_UUID,
    BLEUTOOTH_QUICKSHARE_RECEIVE_UUID,
    BLUETOOTH_QUICKSHARE_NEW_UUID,
]


class BluetoothDevice:
    def __init__(self, name: str, address: str, channel: int) -> None:
        self.name = name
        self.address = address
        self.channel = channel
        self.endpoint_info = parse_bluetooth_device_name(name)

    def __repr__(self) -> str:  # noqa: D105
        return (
            f"BluetoothDevice(name={self.name!r}, "
            f"address={self.address!r}, "
            f"channel={self.channel!r} "
            f"endpoint_info={self.endpoint_info!r})"
        )


async def find_receiving_devices() -> AsyncGenerator[BluetoothDevice, None]:
    logger.debug("Connecting to the system bus")
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    logger.info("Connected to the system bus")

    bluez_root = await get_proxy_object(
        bus,
        "org.bluez",
        "/",
    )

    object_manager = bluez_root.get_interface("org.freedesktop.DBus.ObjectManager")
    objects = await object_manager.call_get_managed_objects()

    adapter_path = None
    for path, interfaces in objects.items():
        if "org.bluez.Adapter1" in interfaces:
            logger.debug("Found adapter at %s", path)
            adapter_path = path
            break

    if adapter_path is None:
        logger.error("No Bluetooth adapter found")
        return

    queue: asyncio.Queue[str] = asyncio.Queue()

    for path, interface in objects.items():
        if "org.bluez.Device1" in interface:
            await queue.put(path)

    register_new_devices(object_manager, queue)

    adapter_proxy = await get_proxy_object(bus, "org.bluez", adapter_path)
    adapter = adapter_proxy.get_interface("org.bluez.Adapter1")
    await adapter.call_start_discovery()

    while True:
        path = await queue.get()
        device_proxy = await get_proxy_object(bus, "org.bluez", path)
        device = device_proxy.get_interface("org.bluez.Device1")
        uuids = [u.casefold() for u in await device.get_uui_ds()]
        if BLEUTOOTH_QUICKSHARE_UUID in uuids:
            name = await device.get_name()
            address = await device.get_address()
            logger.info("Found QuickShare device: %s (%s) at %s", name, address, path)

            channel = cast(
                int,
                rfcomm.find_rfcomm_channel(address, BLEUTOOTH_QUICKSHARE_UUID),  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType]
            )

            yield BluetoothDevice(name, address, channel)


def register_new_devices(object_manager: Any, queue: asyncio.Queue[str]) -> None:
    def on_interfaces_added(object_path: str, interfaces: dict[str, Any]) -> None:
        if "org.bluez.Device1" in interfaces:
            logger.debug("Found new device at %s", object_path)
            queue.put_nowait(object_path)

    object_manager.on_interfaces_added(on_interfaces_added)


async def connect_bluetooth_device(device: BluetoothDevice) -> socket.socket:
    logger.info(
        "Connecting to device %s (%s) on channel %d", device.name, device.address, device.channel
    )

    sock = rfcomm.open_rfcomm_socket()
    rfcomm.connect_rfcomm(sock.fileno(), device.address, device.channel)  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType]
    logger.info(
        "Connected to device %s (%s) on channel %d", device.name, device.address, device.channel
    )

    return sock


_BLUEZ_PATH = "/org/bluez"
"""ProfileManager1 and AgentManager1 live here, not on the root object."""

_PROFILE_PATH = "/de/pyquickshare/QuickShareProfile"
_ADVERTISEMENT_PATH = "/de/pyquickshare/QuickShareAdvertisement"

VERSION_AND_PCP = 0x23
"""Version 1 in the upper 3 bits, PCP 3 in the lower 5. Matches make_service_name."""

SERVICE_ID_HASH = (0xFC, 0x9F, 0x5E)
"""SHA-256 of the Quick Share service ID, truncated to 3 bytes."""

QUICKSHARE_LE_PSM = 0x0090
"""L2CAP PSM published for off-network transfers, in the LE dynamic range.

A sender reads this out of our advertisement and opens an LE L2CAP channel to
it. It was previously filled with random bytes, so the phone dutifully connected
to a different, unbound PSM on every run -- observed as 144 on one attempt and 63
on the next, each refused by the kernel with "PSM not supported".
"""

RFCOMM_CHANNEL = 8
"""Channel published for the Quick Share service.

Any free channel works, since senders resolve it over SDP rather than assuming
one. It is fixed rather than allocated so a firewall or audit has something
stable to refer to.
"""

_MAC_LENGTH = 6
_RECEIVE_ADVERTISEMENT_HEADER = 0x48
_RECEIVE_ADVERTISEMENT_PREFIX_LENGTH = 8
"""Header, service_id_hash and the three unknown zero bytes, before the body."""

ENDPOINT_ID_LENGTH = 4
MAX_ENDPOINT_INFO_LENGTH = 131
"""The layout gives endpoint_info a single length byte, and Quick Share caps it here."""


def make_bluetooth_device_name(endpoint_id: bytes, endpoint_info: bytes) -> str:
    """Build the Bluetooth adapter name a Quick Share sender expects to find.

    Inverse of :func:`parse_bluetooth_device_name`; see the byte layout
    documented there. Sending devices read the adapter's name and decode our
    endpoint info out of it, so this is what makes a machine discoverable as a
    Quick Share target without any shared network.

    Args:
        endpoint_id: Exactly 4 ASCII bytes, as from ``generate_endpoint_id``.
        endpoint_info: The raw ``n`` record blob from ``make_n``.
    """
    if len(endpoint_id) != ENDPOINT_ID_LENGTH:
        msg = f"endpoint_id must be {ENDPOINT_ID_LENGTH} bytes, got {len(endpoint_id)}"
        raise ValueError(msg)

    if len(endpoint_info) > MAX_ENDPOINT_INFO_LENGTH:
        msg = (
            f"endpoint_info must be at most {MAX_ENDPOINT_INFO_LENGTH} bytes, "
            f"got {len(endpoint_info)}"
        )
        raise ValueError(msg)

    blob = bytearray()
    blob.append(VERSION_AND_PCP)
    blob.extend(endpoint_id)
    blob.extend(SERVICE_ID_HASH)
    blob.append(0x00)  # field byte; bit 0 would flag WebRTC connectable
    blob.extend(bytes(6))  # reserved
    blob.append(len(endpoint_info))
    blob.extend(endpoint_info)
    # No UWB address; the trailing optional field is simply omitted.

    return to_url64(blob)


def make_advertisement_trailer(bluetooth_mac: bytes, psm: int = QUICKSHARE_LE_PSM) -> bytes:
    """Build the trailing block that tells a sender where to connect.

    Captured from three real advertisements across two Android phones. The first
    six bytes are the device's Bluetooth Classic address, verbatim: a phone seen
    at ``20:3B:34:6E:27:E1`` advertised a trailer starting ``203b346e27e1``.

    This is very likely what makes off-network transfers possible at all. BLE
    carries only discovery; the transfer itself runs over RFCOMM, and without an
    address in the advertisement a sender has discovered a receiver it has no way
    to reach. It matches the observed failure, where a phone with Wi-Fi disabled
    never opened a Bluetooth connection at all.

    Offsets 8 and 9 are the L2CAP PSM the sender should connect to, little
    endian. That was established by accident and then confirmed: filling them
    with random bytes made the phone request a different PSM on every run -- 144
    once, 63 the next -- each refused by the kernel as unbound. ``01 00`` at
    offsets 10 and 11 held across every capture from both devices. Offset 12
    varies and is still unidentified.
    """
    if len(bluetooth_mac) != _MAC_LENGTH:
        msg = f"bluetooth_mac must be {_MAC_LENGTH} bytes, got {len(bluetooth_mac)}"
        raise ValueError(msg)

    trailer = bytearray(bluetooth_mac)
    trailer.extend((0x00, 0x00))
    # The L2CAP PSM a sender should connect to, little endian. This is what
    # varied between captures; filling it with random bytes sent the phone to an
    # unbound PSM every time.
    trailer.extend(psm.to_bytes(2, "little"))
    trailer.extend((0x01, 0x00))  # constant across every capture seen
    # Deterministic while the remaining fields are being identified: a random
    # value here is indistinguishable from a field we are filling in wrongly.
    trailer.append(0x00)
    return bytes(trailer)


def parse_mac(address: str) -> bytes:
    """Turn a BlueZ address string such as 'F4:6D:3F:60:C7:E5' into bytes."""
    return bytes.fromhex(address.replace(":", ""))


def make_receive_advertisement(
    endpoint_id: bytes,
    endpoint_info: bytes,
    trailer: bytes = b"",
) -> bytes:
    """Build the BLE service data that marks us as a Quick Share receiver.

    Setting the Bluetooth Classic adapter name is not enough to be offered as a
    target: Android discovers receivers by scanning for BLE service data under
    :data:`BLEUTOOTH_QUICKSHARE_RECEIVE_UUID`. A device advertising only over
    Classic shows up in the phone's Bluetooth list but never in Quick Share.

    The layout was recovered by capturing a real advertisement from an Android
    phone with "visible to everyone" set (see ``tools/scan_quickshare.py``)::

        [0]      0x48            header
        [1:4]    fc9f5e          service_id_hash
        [4:7]    000000          unknown, zero on every capture
        [7]      0x31            offset at which the trailer starts
        [8]      0x23            version_and_pcp
        [9:12]   fc9f5e          service_id_hash again
        [12:16]  b"42ZB"         endpoint_id, 4 ASCII alphanumerics
        [16]     0x20            length of the endpoint info that follows
        [17:49]  ...             endpoint info, exactly what make_n builds
        [49:62]  ...             13 byte trailer of unknown meaning

    The trailer is omitted: its meaning is unknown, and copying 13 bytes lifted
    from another device's advertisement would be worse than leaving them out,
    since some of them plainly vary per device.
    """
    if len(endpoint_id) != ENDPOINT_ID_LENGTH:
        msg = f"endpoint_id must be {ENDPOINT_ID_LENGTH} bytes, got {len(endpoint_id)}"
        raise ValueError(msg)

    if len(endpoint_info) > MAX_ENDPOINT_INFO_LENGTH:
        msg = f"endpoint_info must be at most {MAX_ENDPOINT_INFO_LENGTH} bytes"
        raise ValueError(msg)

    body = bytearray()
    body.append(VERSION_AND_PCP)
    body.extend(SERVICE_ID_HASH)
    body.extend(endpoint_id)
    body.append(len(endpoint_info))
    body.extend(endpoint_info)

    blob = bytearray()
    blob.append(_RECEIVE_ADVERTISEMENT_HEADER)
    blob.extend(SERVICE_ID_HASH)
    blob.extend((0x00, 0x00, 0x00))
    # Offset at which the trailer begins, which every capture agreed on.
    blob.append(len(body) + _RECEIVE_ADVERTISEMENT_PREFIX_LENGTH)
    blob.extend(body)
    blob.extend(trailer)

    return bytes(blob)


async def advertise_over_bluetooth(
    *,
    endpoint_id: bytes,
    endpoint_info: bytes,
    on_connection: Callable[[int, str], None],
) -> BluetoothAdvertisement | None:
    """Become discoverable as a Quick Share target over Bluetooth Classic.

    Three things have to be true before a phone will offer to send to us with no
    network: the Quick Share RFCOMM service must be published over SDP, the
    adapter must be discoverable, and the adapter's name must carry our encoded
    endpoint info, which is where senders read it from.

    That last one mutates a system-wide, user-visible setting, so the previous
    alias is captured here and must be restored -- see
    :meth:`BluetoothAdvertisement.stop`. Leaving a machine called
    ``I1h1Tmf8n14AAA`` in everyone's Bluetooth list would be rude.

    Returns:
        A handle to stop advertising with, or ``None`` if Bluetooth is
        unavailable. Missing Bluetooth is not fatal: LAN receiving still works.
    """
    try:
        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    except Exception:  # noqa: BLE001 - any BlueZ failure means no Bluetooth, which is survivable
        logger.info("Could not reach BlueZ, not advertising over Bluetooth")
        return None

    try:
        root = await get_proxy_object(bus, "org.bluez", "/")
        adapter_path = await get_bluetooth_adapter_path(root)
        adapter_proxy = await get_proxy_object(bus, "org.bluez", adapter_path)
        adapter = adapter_proxy.get_interface("org.bluez.Adapter1")

        # Captured before we overwrite them so they can be put back.
        previous_alias = await adapter.get_alias()
        previous_discoverable = await adapter.get_discoverable()
        previous_timeout = await adapter.get_discoverable_timeout()

        profile = _QuickShareProfile(on_connection)
        bus.export(_PROFILE_PATH, profile)

        # ProfileManager1 lives on /org/bluez. The root object only carries
        # ObjectManager, which is what the adapter lookup above walks.
        manager_proxy = await get_proxy_object(bus, "org.bluez", _BLUEZ_PATH)
        manager = manager_proxy.get_interface("org.bluez.ProfileManager1")
        await manager.call_register_profile(
            _PROFILE_PATH,
            BLEUTOOTH_QUICKSHARE_UUID,
            {
                "Name": Variant("s", "Quick Share"),
                "Role": Variant("s", "server"),
                # Without an explicit Channel, BlueZ publishes a service record
                # whose ProtocolDescriptorList contains L2CAP alone. A sender
                # then resolves our UUID over SDP, finds no RFCOMM layer and so
                # no channel to open, and gives up: observed as an ACL link that
                # comes up, exchanges SDP, and is torn down seconds later.
                # Naming a channel makes BlueZ emit [[L2CAP], [RFCOMM, n]].
                "Channel": Variant("q", RFCOMM_CHANNEL),
                "RequireAuthentication": Variant("b", False),
                "RequireAuthorization": Variant("b", False),
            },
        )

        # Classic name: how a sender enumerating Bluetooth devices reads our
        # endpoint info. Necessary, but on its own it only puts us in the phone's
        # Bluetooth list, not in Quick Share.
        await adapter.set_alias(make_bluetooth_device_name(endpoint_id, endpoint_info))

        # BLE presence: what Android actually scans for to find receivers.
        # The trailer carries this adapter's Bluetooth address, which is how a
        # sender knows where to open the RFCOMM connection after discovery.
        adapter_address = parse_mac(await adapter.get_address())
        advertisement = _ReceiveAdvertisement(
            make_receive_advertisement(
                endpoint_id,
                endpoint_info,
                make_advertisement_trailer(adapter_address),
            ),
        )
        bus.export(_ADVERTISEMENT_PATH, advertisement)
        le_manager = adapter_proxy.get_interface("org.bluez.LEAdvertisingManager1")
        await le_manager.call_register_advertisement(_ADVERTISEMENT_PATH, {})
        logger.debug("Registered Quick Share BLE presence advertisement")

        # DiscoverableTimeout defaults to 180 seconds, after which BlueZ clears
        # Discoverable again. Left alone, discovery would simply stop working
        # three minutes in, with nothing in the log to say why. Zero means "until
        # told otherwise", and the original value is restored on stop.
        await adapter.set_discoverable_timeout(0)
        await adapter.set_discoverable(True)
    except Exception:
        logger.exception("Failed to advertise over Bluetooth, receiving over the network only")
        with contextlib.suppress(Exception):
            bus.disconnect()
        return None

    logger.debug("Advertising as a Quick Share target over Bluetooth")
    return BluetoothAdvertisement(
        bus=bus,
        adapter=adapter,
        adapter_proxy=adapter_proxy,
        previous_alias=previous_alias,
        previous_discoverable=previous_discoverable,
        previous_timeout=previous_timeout,
    )


class BluetoothAdvertisement:
    """Undoes everything :func:`advertise_over_bluetooth` changed."""

    def __init__(  # noqa: PLR0913 - all keyword-only, each one a value to restore
        self,
        *,
        bus: MessageBus,
        adapter: Any,
        adapter_proxy: Any,
        previous_alias: str,
        previous_discoverable: bool,
        previous_timeout: int,
    ) -> None:
        self._bus = bus
        self._adapter = adapter
        self._adapter_proxy = adapter_proxy
        self._previous_alias = previous_alias
        self._previous_discoverable = previous_discoverable
        self._previous_timeout = previous_timeout
        self._stopped = False

    async def stop(self) -> None:
        """Restore the adapter, best effort, exactly once.

        Runs during shutdown, so every step is attempted independently: failing
        to unregister the profile must not leave the user's adapter named after
        an encoded endpoint blob.
        """
        if self._stopped:
            return
        self._stopped = True

        with contextlib.suppress(Exception):
            le_manager = self._adapter_proxy.get_interface("org.bluez.LEAdvertisingManager1")
            await le_manager.call_unregister_advertisement(_ADVERTISEMENT_PATH)
        with contextlib.suppress(Exception):
            self._bus.unexport(_ADVERTISEMENT_PATH)
        with contextlib.suppress(Exception):
            await self._adapter.set_alias(self._previous_alias)
        with contextlib.suppress(Exception):
            await self._adapter.set_discoverable(self._previous_discoverable)
        with contextlib.suppress(Exception):
            await self._adapter.set_discoverable_timeout(self._previous_timeout)
        with contextlib.suppress(Exception):
            manager_proxy = await get_proxy_object(self._bus, "org.bluez", _BLUEZ_PATH)
            manager = manager_proxy.get_interface("org.bluez.ProfileManager1")
            await manager.call_unregister_profile(_PROFILE_PATH)
        with contextlib.suppress(Exception):
            self._bus.disconnect()

        logger.debug("Stopped advertising over Bluetooth, adapter restored")


async def get_bluetooth_adapter_path(root_obj: Any) -> str:
    """Return the object path of the first Bluetooth adapter."""
    object_manager = root_obj.get_interface("org.freedesktop.DBus.ObjectManager")
    objects = await object_manager.call_get_managed_objects()

    for path, interfaces in objects.items():
        if "org.bluez.Adapter1" in interfaces:
            return path

    msg = "No Bluetooth adapter found"
    raise RuntimeError(msg)


def parse_bluetooth_device_name(name: str) -> EndpointInfo:
    # Offset	Size	    Field	               Notes
    # 0	        1 byte	    version_and_pcp	       Upper 3 bits = version, lower 5 bits = PCP
    # 1	        4 bytes	    endpoint_id	           Raw ASCII chars
    # 5	        3 bytes	    service_id_hash	       SHA-256 of service ID, truncated
    # 8	        1 byte	    field_byte	           Bit 0 = WebRTC connectable flag
    # 9	        6 bytes	    (reserved)	           Skipped/ignored
    # 15	    1 byte	    endpoint_info_length   Length of the next field
    # 16	    N bytes	    endpoint_info	       Capped at 131 bytes
    # 16+N	    1 byte	    uwb_address_length	   Optional if bytes remain
    # 17+N	    M bytes	    uwb_address	Optional   UWB address (2 or 8 bytes)

    blob = from_url64(name)

    version_and_pcp = blob[0]
    _version = version_and_pcp >> 5
    _pcp = version_and_pcp & 0b00011111

    _endpoint_id = blob[1:5]
    _service_id_hash = blob[5:8]
    field_byte = blob[8]
    _webrtc_connectable = bool(field_byte & 0b00000001)

    endpoint_info_length = blob[15]
    endpoint_info = blob[16 : 16 + endpoint_info_length]

    return parse_endpoint_info(to_url64(endpoint_info).encode("utf-8"))
