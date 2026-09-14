# ruff: noqa: PGH003
# the mDNS part of Quick Share
from __future__ import annotations

import asyncio
import io
import os
import random
import socket
from contextlib import closing, suppress
from logging import getLogger
from typing import NamedTuple

import dbus_next
import ifaddr
from zeroconf import IPVersion
from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf

from ..common import NETWORK_BASE_PATH, InterfaceInfo, Type, from_url64, to_url64
from ..dbus.firewalld import temporarily_open_port

logger = getLogger(__name__)


def get_interfaces() -> list[str]:
    interfaces: list[str] = []
    for ifa in NETWORK_BASE_PATH.iterdir():
        carrier = ifa.joinpath("carrier")
        with suppress(OSError):
            if (
                "/devices/virtual/net/" not in ifa.resolve().as_posix()
                and carrier.exists()
                and carrier.read_text().strip() == "1"
            ):
                interfaces.append(ifa.name)
    return interfaces


class IPV4Runner:
    def __init__(self) -> None:
        self.aiozc: AsyncZeroconf | None = None

    async def register_services(self, infos: list[AsyncServiceInfo]) -> None:
        self.aiozc = AsyncZeroconf(ip_version=IPVersion.V4Only)
        tasks = [self.aiozc.async_register_service(info) for info in infos]  # type: ignore
        background_tasks = await asyncio.gather(*tasks)  # type: ignore
        await asyncio.gather(*background_tasks)  # type: ignore
        logger.debug("Registered %d services", len(infos))

        await asyncio.Event().wait()

    async def unregister_services(self, infos: list[AsyncServiceInfo]) -> None:
        assert self.aiozc is not None  # noqa: S101 - escape hatch for the type checker
        tasks = [self.aiozc.async_unregister_service(info) for info in infos]  # type: ignore
        background_tasks = await asyncio.gather(*tasks)  # type: ignore
        await asyncio.gather(*background_tasks)  # type: ignore
        await self.aiozc.async_close()


def make_service_name(endpoint_id: bytes) -> bytearray:
    array = bytearray()

    array.append(0x23)  # PCP
    logger.debug("endpoint_id: %s", endpoint_id)
    array.extend(endpoint_id)
    array.extend((0xFC, 0x9F, 0x5E))  # Service ID
    array.extend((0x00, 0x00))  # ¯\_(ツ)_/¯

    return array


class EndpointInfo(NamedTuple):
    visible: bool
    type: Type
    name: str | None
    records: dict[int, bytes]


def parse_endpoint_info(n: bytes) -> EndpointInfo:
    decoded = from_url64(n.decode("utf-8"))
    buffer = io.BytesIO(decoded)
    flags = buffer.read(1)[0]
    visible = ((flags >> 4) & 1) == 0
    device_type = Type(flags >> 1 & 0b00000111)

    buffer.read(2)  # skip 2 bytes of "salt"
    buffer.read(14)  # skip 14 bytes of "encrypted metadata key"

    name = None

    if visible:
        name_length = buffer.read(1)[0]  # length byte
        name = buffer.read(name_length).decode("utf-8")  # name bytes

    records: dict[int, bytes] = {}
    while buffer.tell() < buffer.getbuffer().nbytes:
        type_ = buffer.read(1)[0]
        length = buffer.read(1)[0]
        value = buffer.read(length)
        records[type_] = value

    return EndpointInfo(visible, device_type, name, records)


def make_n(*, visible: bool, type: Type, name: bytes) -> bytearray:
    """Build the endpoint info blob advertised as the mDNS ``n`` record.

    Layout, matching :func:`parse_endpoint_info`:

    ==========  =====  =================================================
    Offset      Size   Field
    ==========  =====  =================================================
    0           1      flags: reserved (3) visibility (1) type (3) pad (1)
    1           2      salt
    3           14     encrypted metadata key
    17          1      length of name
    18          N      name, UTF-8
    ==========  =====  =================================================

    The flags byte previously had the constant 2 written into it, ignoring both
    arguments, which decodes as type ``phone`` regardless of what the caller
    asked for -- so a laptop advertised itself as a phone, and ``visible=False``
    did nothing.
    """
    n = bytearray()

    # Visibility is inverted on the wire: the bit is set when hidden.
    flags = (0 if visible else 1) << 4 | (type.value & 0b111) << 1
    n.append(flags)

    # 2 bytes of salt followed by a 14 byte encrypted metadata key. We do not
    # implement contact-based visibility, so these only need to be non-constant.
    n.extend(random.randbytes(16))  # noqa: S311 - not used for anything sensitive
    n.append(len(name))
    n.extend(name)
    return n


async def make_service(
    *,
    visible: bool,
    type_: Type,
    name: bytes,
    endpoint_id: bytes,
    interface_info: InterfaceInfo,
) -> AsyncServiceInfo:
    _name = to_url64(make_service_name(endpoint_id))
    n = make_n(visible=visible, type=type_, name=name)

    return AsyncServiceInfo(
        "_FC9F5ED42C8A._tcp.local.",
        f"{_name}._FC9F5ED42C8A._tcp.local.",
        port=interface_info.port,
        parsed_addresses=interface_info.ips,
        properties={"n": to_url64(n)},
    )


async def get_interface_info() -> InterfaceInfo:
    ips: list[str] = []

    ip = os.environ.get("QUICKSHARE_IP")
    used_interfaces: set[str] = set()

    if ip is None:
        interfaces = get_interfaces()
        for adapter in ifaddr.get_adapters():
            if adapter.name not in interfaces:
                continue

            used_interfaces.add(adapter.name)
            ips.extend(str(ip.ip) for ip in adapter.ips if isinstance(ip.ip, str))

        logger.debug("QUICKSHARE_IP not set, using: %s", ", ".join(ips))
    else:
        ips.append(ip)

    # A random port is incompatible with a static firewall (ufw, nftables), which
    # can only be told about a port known ahead of time. QUICKSHARE_PORT pins it so
    # a single firewall rule keeps working across restarts.
    configured_port = os.environ.get("QUICKSHARE_PORT")
    if configured_port is not None:
        port = int(configured_port)
        logger.debug("QUICKSHARE_PORT set, using: %d", port)
    else:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
            sock.bind(("0.0.0.0", 0))  # noqa: S104 - we only care about the port
            _, port = sock.getsockname()

    try:
        for interface in used_interfaces:
            await temporarily_open_port(interface, port)
    except dbus_next.errors.DBusError as e:
        if e.text == "The name is not activatable":
            # firewalld simply is not installed. That is the normal case on
            # distributions that ship ufw, nftables or no firewall at all, so it
            # is not an error -- and a traceback here wrongly suggests the
            # transfer is broken when the port may well be open already.
            logger.info(
                "firewalld is not available, not opening port %d automatically. "
                "If transfers stall, allow TCP %d in your firewall.",
                port,
                port,
            )
        else:
            logger.warning(
                "Failed to open port %d via firewalld: %s. "
                "You may need to open it on your firewall manually.",
                port,
                e.text,
            )
    except Exception:
        logger.exception("Failed to open port %d via firewalld", port)

    logger.debug("Using port %d", port)

    return InterfaceInfo(ips=ips, port=port)
