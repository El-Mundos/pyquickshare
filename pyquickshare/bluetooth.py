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

VERSION_AND_PCP = 0x23
"""Version 1 in the upper 3 bits, PCP 3 in the lower 5. Matches make_service_name."""

SERVICE_ID_HASH = (0xFC, 0x9F, 0x5E)
"""SHA-256 of the Quick Share service ID, truncated to 3 bytes."""

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
                # BlueZ picks a free channel and publishes it over SDP.
                "RequireAuthentication": Variant("b", False),
                "RequireAuthorization": Variant("b", False),
            },
        )

        await adapter.set_alias(make_bluetooth_device_name(endpoint_id, endpoint_info))
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
        previous_alias=previous_alias,
        previous_discoverable=previous_discoverable,
        previous_timeout=previous_timeout,
    )


class BluetoothAdvertisement:
    """Undoes everything :func:`advertise_over_bluetooth` changed."""

    def __init__(
        self,
        *,
        bus: MessageBus,
        adapter: Any,
        previous_alias: str,
        previous_discoverable: bool,
        previous_timeout: int,
    ) -> None:
        self._bus = bus
        self._adapter = adapter
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
