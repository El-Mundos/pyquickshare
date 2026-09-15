"""Quick Share implementation in Python."""

from __future__ import annotations

import asyncio
import contextlib
import enum
import math
import os
import socket
import struct
import time
from logging import getLogger
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, cast

from .backend import EncryptedBackend
from .common import (
    InterfaceInfo,
    Type,
    create_task,
    derive_endpoint_id_from_mac,
    generate_connection_response,
    generate_paired_key_encryption,
    pick_mac_deterministically,
    safe_assert,
)
from .bluetooth import QUICKSHARE_LE_PSM, BluetoothAdvertisement, advertise_over_bluetooth
from .connection import NearbyConnection
from .mdns.receive import (
    IPV4Runner,
    get_interface_info,
    get_interfaces,
    make_n,
    make_service,
)
from .protos import offline_wire_formats, wire_format
from .results import FileResult, Result, TextResult, WifiResult
from .sinks import FileSink, MemorySink, PayloadSink, safe_file_name, unique_path
from .ukey2 import do_server_key_exchange

NAME = "pyquickshare"

logger = getLogger(__name__)

_advertisements: list[BluetoothAdvertisement] = []
"""Live Bluetooth advertisements, so the adapter can be restored on shutdown."""

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from zeroconf.asyncio import AsyncServiceInfo


def default_download_dir() -> Path:
    """Where received files are written unless told otherwise.

    This used to be the relative path ``downloads/``, which resolved against the
    process working directory -- so where a file landed depended on where the
    program happened to be started from, and receiving failed outright if the
    directory did not already exist.
    """
    configured = os.environ.get("QUICKSHARE_DOWNLOAD_DIR")
    if configured:
        return Path(configured).expanduser()

    xdg = os.environ.get("XDG_DOWNLOAD_DIR")
    return Path(xdg).expanduser() if xdg else Path.home() / "Downloads"


__all__ = (
    "ShareRequest",
    "receive",
    "stop_advertising",
)


async def stop_advertising() -> None:
    """Restore anything advertising changed system-wide.

    Advertising over Bluetooth renames the user's adapter and makes it
    discoverable. Both are visible to every device nearby and outlive this
    process, so callers must invoke this on shutdown -- including on Ctrl-C --
    or the machine is left called something like ``I1h1Tmf8n14AAA``.
    """
    while _advertisements:
        await _advertisements.pop().stop()


def to_pin(bytes_: bytes) -> str:
    k_hash_modulo = 9973
    k_hash_base_multiplier = 31

    hash = 0
    multiplier = 1
    for byte in struct.unpack("b" * len(bytes_), bytes_):
        # % in python is real mod, not remainder, unlike in C++ (worst bug i ever had to debug)
        hash = int(math.fmod((hash + byte * multiplier), k_hash_modulo))
        multiplier = int(
            math.fmod((multiplier * k_hash_base_multiplier), k_hash_modulo),
        )

    return f"{abs(hash):04d}"


class ShareRequest:
    """An incoming offer, surfaced before it is accepted.

    A GUI needs to tell the user who is sending and what, which means the offer
    has to carry the introduction's metadata rather than just a raw header.
    """

    def __init__(
        self,
        header: offline_wire_formats.PayloadTransferFramePayloadHeader,
        pin: str,
        *,
        sender: str = "",
        mode: ReceiveMode | None = None,
        items: list[ShareItem] | None = None,
    ) -> None:
        self.respond: asyncio.Future[bool] = asyncio.Future()
        self.done: asyncio.Future[list[Result]] = asyncio.Future()
        self.header: offline_wire_formats.PayloadTransferFramePayloadHeader = header
        self.pin: str = pin
        self.sender: str = sender
        self.mode: ReceiveMode | None = mode
        self.items: list[ShareItem] = items or []
        self.on_progress: Callable[[int, int], None] | None = None
        """Called with (bytes received, total bytes) as the transfer runs."""

    @property
    def total_size(self) -> int:
        """Total bytes offered, across every item."""
        return sum(item.size for item in self.items)

    async def accept(self) -> list[Result]:
        self.respond.set_result(True)
        return await self.done

    async def reject(self) -> None:
        self.respond.set_result(False)
        await self.done


class ShareItem(NamedTuple):
    """One thing being offered, known before the transfer starts."""

    name: str
    size: int
    mime_type: str = ""


class ReceiveMode(enum.Enum):
    WIFI = 1
    FILES = 2
    TEXT = 3


def _generate_accept() -> wire_format.Frame:
    return wire_format.Frame(
        version=wire_format.FrameVersion.V1,
        v1=wire_format.V1Frame(
            type=wire_format.V1FrameFrameType.RESPONSE,
            connection_response=wire_format.ConnectionResponseFrame(
                status=wire_format.ConnectionResponseFrameStatus.ACCEPT,
            ),
        ),
    )


def _generate_reject() -> wire_format.Frame:
    """Tell the sender we are declining, rather than going silent.

    Staying quiet leaves the sending device waiting until it times out, which
    reads as a hung transfer rather than a refusal.
    """
    return wire_format.Frame(
        version=wire_format.FrameVersion.V1,
        v1=wire_format.V1Frame(
            type=wire_format.V1FrameFrameType.RESPONSE,
            connection_response=wire_format.ConnectionResponseFrame(
                status=wire_format.ConnectionResponseFrameStatus.REJECT,
            ),
        ),
    )


class ReceiveConnection(NearbyConnection):
    async def _reject_introduction(self) -> None:
        """Decline an offer, best effort.

        The caller is already tearing the connection down, so a send failure here
        changes nothing -- the sender sees a closed connection either way.
        """
        try:
            await self.send_frame(_generate_reject())
        except Exception:
            logger.exception("Failed to send rejection, closing anyway")

    async def _exchange_connection_response_server(self) -> None:
        """Read CONNECTION_RESPONSE, send ours."""
        data = await self._backend.recv()
        client_response = offline_wire_formats.OfflineFrame().parse(data)
        os_name = offline_wire_formats.OsInfoOsType(
            client_response.v1.connection_response.os_info.type,
        ).name
        logger.debug("Client OS: %s", os_name)
        connection_response = generate_connection_response()
        await self._backend.send(bytes(connection_response))

    async def upgrade_server(self) -> bool:
        keychain = await do_server_key_exchange(self._backend)
        if keychain is None:
            return False
        await self._exchange_connection_response_server()
        self._backend = EncryptedBackend(
            self._backend.reader,
            self._backend.writer,
            keychain,
        )
        return True

    async def receive_loop(  # noqa: C901 PLR0912 PLR0915
        self,
        requests: asyncio.Queue[ShareRequest],
        name: str,
        *,
        download_dir: Path | None = None,
    ) -> None:
        receive_mode: ReceiveMode | None = None
        expected_payload_ids: dict[
            int,
            wire_format.WifiCredentialsMetadata
            | wire_format.FileMetadata
            | wire_format.TextMetadata,
        ] = {}

        request: ShareRequest | None = None
        results: list[Result] = []
        directory = download_dir or default_download_dir()
        # Where each file payload is being streamed, so the completed payload can
        # be reported at the path it actually landed on.
        file_paths: dict[int, Path] = {}
        progress_total = 0

        def open_sink(
            header: offline_wire_formats.PayloadTransferFramePayloadHeader,
        ) -> PayloadSink:
            """Stream file payloads to disk; keep everything else in memory.

            Text, Wi-Fi credentials and control frames are small and get parsed
            as a whole, so buffering them costs nothing. Files are unbounded.
            """
            if receive_mode is not ReceiveMode.FILES or header.id not in expected_payload_ids:
                return MemorySink()

            path = unique_path(directory, safe_file_name(header.file_name))
            file_paths[header.id] = path
            logger.debug("Streaming payload %d to %s", header.id, path)
            return FileSink(path)

        def on_progress(
            _header: offline_wire_formats.PayloadTransferFramePayloadHeader,
            received: int,
        ) -> None:
            if request is None or request.on_progress is None:
                return
            # header.total_size is this payload; the offer may span several.
            request.on_progress(progress_total + received, request.total_size)

        async for payload_header, data in self.iter_payloads(
            open_sink=open_sink,
            on_progress=on_progress,
        ):
            if payload_header.id in expected_payload_ids:
                metadata = expected_payload_ids.pop(payload_header.id)

                if receive_mode is ReceiveMode.FILES:
                    metadata = cast(wire_format.FileMetadata, metadata)

                    # Already streamed to disk by FileSink; nothing to write here.
                    path = file_paths.pop(payload_header.id)
                    progress_total += payload_header.total_size
                    logger.debug("Received file, saved to %s", path)

                    results.append(
                        FileResult(
                            name=path.name,
                            path=str(path),
                            size=payload_header.total_size,
                        ),
                    )
                elif receive_mode is ReceiveMode.WIFI:
                    metadata = cast(wire_format.WifiCredentialsMetadata, metadata)
                    # Non-file payloads use MemorySink, so data is always bytes.
                    safe_assert(data is not None, "wifi payload arrived without data")

                    credentials = wire_format.WifiCredentials().parse(data)

                    logger.debug(
                        "Received wifi credentials payload for ssid %r",
                        metadata.ssid,
                    )

                    results.append(
                        WifiResult(
                            ssid=metadata.ssid,
                            password=credentials.password,
                            security_type=metadata.security_type,
                        ),
                    )
                elif receive_mode is ReceiveMode.TEXT:
                    metadata = cast(wire_format.TextMetadata, metadata)
                    safe_assert(data is not None, "text payload arrived without data")

                    logger.debug("Received text %d", payload_header.id)

                    results.append(
                        TextResult(
                            title=metadata.text_title,
                            text=data.decode("utf-8"),
                        ),
                    )

            else:
                # Control frames are never streamed to disk.
                safe_assert(data is not None, "control frame arrived without data")
                wire_frame = wire_format.Frame().parse(data)

                if wire_frame.v1.type == wire_format.V1FrameFrameType.PAIRED_KEY_RESULT:
                    # we know we failed this, and we just mirror the response
                    await self.send_frame(wire_frame)
                elif wire_frame.v1.type == wire_format.V1FrameFrameType.PAIRED_KEY_ENCRYPTION:
                    # we don't really care about this
                    ...
                elif wire_frame.v1.type == wire_format.V1FrameFrameType.INTRODUCTION:
                    if wire_frame.v1.introduction.wifi_credentials_metadata:
                        wifi_metadata = wire_frame.v1.introduction.wifi_credentials_metadata
                        receive_mode = ReceiveMode.WIFI
                        logger.debug(
                            "%r wants to send wifi credentials for ssids %r",
                            name,
                            ", ".join(m.ssid for m in wifi_metadata),
                        )

                        request = ShareRequest(
                            payload_header,
                            to_pin(self.auth_string),
                            sender=name,
                            mode=receive_mode,
                            items=[ShareItem(name=m.ssid, size=0) for m in wifi_metadata],
                        )
                        await requests.put(request)

                        # Credentials join a network on the user's behalf; that is
                        # not something to take without asking.
                        if not await request.respond:
                            logger.debug("Rejecting wifi credentials")
                            await self._reject_introduction()
                            break

                        expected_payload_ids.update({m.payload_id: m for m in wifi_metadata})
                        await self.send_frame(_generate_accept())

                    elif wire_frame.v1.introduction.file_metadata:
                        file_metadata = wire_frame.v1.introduction.file_metadata
                        logger.debug(
                            "%r wants to send %r",
                            name,
                            ", ".join(m.name for m in file_metadata),
                        )

                        receive_mode = ReceiveMode.FILES
                        request = ShareRequest(
                            payload_header,
                            to_pin(self.auth_string),
                            sender=name,
                            mode=receive_mode,
                            items=[
                                ShareItem(
                                    name=safe_file_name(m.name),
                                    size=m.size,
                                    mime_type=m.mime_type,
                                )
                                for m in file_metadata
                            ],
                        )
                        await requests.put(request)
                        result = await request.respond

                        if result:
                            logger.debug("Accepting introduction")
                            await self.send_frame(_generate_accept())
                            expected_payload_ids.update(
                                {m.payload_id: m for m in file_metadata},
                            )
                        else:
                            logger.debug("Rejecting introduction")
                            await self._reject_introduction()
                            break

                    elif wire_frame.v1.introduction.text_metadata:
                        text_metadata = wire_frame.v1.introduction.text_metadata
                        receive_mode = ReceiveMode.TEXT
                        logger.debug("%r wants to send text", name)

                        request = ShareRequest(
                            payload_header,
                            to_pin(self.auth_string),
                            sender=name,
                            mode=receive_mode,
                            items=[
                                ShareItem(name=m.text_title, size=m.size) for m in text_metadata
                            ],
                        )
                        await requests.put(request)

                        if not await request.respond:
                            logger.debug("Rejecting text")
                            await self._reject_introduction()
                            break

                        expected_payload_ids.update(
                            {m.payload_id: m for m in wire_frame.v1.introduction.text_metadata},
                        )

                        await self.send_frame(_generate_accept())
                    else:
                        logger.debug("Received weird introduction %d", payload_header.id)
                else:
                    logger.debug("Received unknown frame %d", payload_header.id)

            if not expected_payload_ids and receive_mode is not None:
                break

        if request and not request.done.done():
            request.done.set_result(results)


async def _handle_client(
    requests: asyncio.Queue[ShareRequest],
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    endpoint_id: bytes,
    download_dir: Path | None = None,
) -> None:
    start = time.perf_counter()
    # A TCP peer is (host, port); an RFCOMM one is (bdaddr, channel). Both are
    # two-tuples, but only describe them generically since this handles either.
    peer = writer.get_extra_info("peername")
    logger.debug("Connection from %s", _format_peer(peer))

    conn = ReceiveConnection(reader, writer, endpoint_id=endpoint_id)

    data = await conn.recv_bytes()
    connection_request = offline_wire_formats.OfflineFrame().parse(data)

    safe_assert(
        connection_request.v1.type == offline_wire_formats.V1FrameFrameType.CONNECTION_REQUEST,
        "Expected first message to be of type CONNECTION_REQUEST",
    )

    device_info = connection_request.v1.connection_request.endpoint_info
    name = device_info[18:].decode("utf-8")
    logger.debug("Received CONNECTION_REQUEST from %r", name)

    if not await conn.upgrade_server():
        return

    logger.debug("Connection established with %r", name)

    conn.start_keep_alive()
    await conn.send_frame(generate_paired_key_encryption())

    await conn.receive_loop(requests, name, download_dir=download_dir)

    duration = time.perf_counter() - start
    logger.debug("Connection with %r closed after %f seconds", name, duration)

    await conn.stop_keep_alive()
    await conn.close()
    with contextlib.suppress(Exception):
        writer.close()
        await writer.wait_closed()


def _format_peer(peer: object) -> str:
    """Describe a peer address without assuming which transport it came from."""
    if isinstance(peer, tuple) and len(peer) == 2:  # noqa: PLR2004
        return f"{peer[0]}:{peer[1]}"
    return repr(peer)


async def _le_l2cap_server(
    requests: asyncio.Queue[ShareRequest],
    *,
    endpoint_id: bytes,
    download_dir: Path | None = None,
) -> bool:
    """Listen on the BLE L2CAP channel Android uses for off-network transfers.

    SOCK_STREAM rather than SOCK_SEQPACKET: both work at the kernel level for a
    credit-based LE channel, but asyncio refuses anything that is not a stream
    socket, and the protocol above wants a byte stream in any case.

    The address is a four-tuple. Python's two-tuple L2CAP form implies BR/EDR and
    is rejected outright for an LE PSM.
    """
    try:
        sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_L2CAP)
    except (AttributeError, OSError):
        logger.info("BLE L2CAP is unavailable, receiving over the network only")
        return False

    try:
        sock.bind(("00:00:00:00:00:00", QUICKSHARE_LE_PSM, 0, socket.BDADDR_LE_PUBLIC))
        sock.setblocking(False)
    except OSError:
        logger.warning(
            "Could not bind LE L2CAP PSM 0x%04x, receiving over the network only",
            QUICKSHARE_LE_PSM,
        )
        sock.close()
        return False

    server = await asyncio.start_server(
        lambda reader, writer: _handle_client(
            requests, reader, writer, endpoint_id=endpoint_id, download_dir=download_dir
        ),
        sock=sock,
    )

    logger.debug("Listening for Quick Share over BLE L2CAP PSM 0x%04x", QUICKSHARE_LE_PSM)
    create_task(server.serve_forever())
    return True


async def _handle_bluetooth_fd(
    requests: asyncio.Queue[ShareRequest],
    fd: int,
    device: str,
    *,
    endpoint_id: bytes,
    download_dir: Path | None = None,
) -> None:
    """Serve a Quick Share session over a socket BlueZ already connected.

    The transport is interchangeable as far as the protocol is concerned --
    everything below wants a reader and a writer -- so a Bluetooth client goes
    through exactly the same path as one that arrived over TCP.
    """
    try:
        sock = socket.socket(fileno=fd)
    except OSError:
        logger.exception("Could not wrap the Bluetooth socket for %s", device)
        return

    try:
        reader, writer = await asyncio.open_connection(sock=sock)
    except OSError:
        logger.exception("Could not open a stream over Bluetooth to %s", device)
        sock.close()
        return

    await _handle_client(
        requests, reader, writer, endpoint_id=endpoint_id, download_dir=download_dir
    )


async def _socket_server(
    requests: asyncio.Queue[ShareRequest],
    *,
    interface_info: InterfaceInfo,
    endpoint_id: bytes,
    download_dir: Path | None = None,
) -> None:
    server = await asyncio.start_server(
        lambda reader, writer: _handle_client(
            requests, reader, writer, endpoint_id=endpoint_id, download_dir=download_dir
        ),
        interface_info.ips,
        interface_info.port,
    )

    await server.serve_forever()


async def receive(
    *,
    endpoint_id: bytes | None = None,
    download_dir: Path | str | None = None,
    name: str | None = None,
    bluetooth: bool = True,
) -> AsyncIterator[ShareRequest]:
    """Receive something over Quick Share. Runs forever.

    This function registers an mDNS service and opens a socket server to receive data.
    If firewalld is available, it temporarily reconfigures firewalld to allow incoming connections on the port.

    Yields:
        ShareRequest: A request to share something

    Example:
        .. code-block:: python

            async for request in receive():
                results = await request.accept()
                print(results)

    """  # noqa: E501
    if endpoint_id and len(endpoint_id) != 4:  # noqa: PLR2004, this is not a magic number
        msg = "endpoint_id must be 4 bytes (and in ASCII)"
        raise ValueError(msg)

    endpoint_id = endpoint_id or derive_endpoint_id_from_mac(
        pick_mac_deterministically(get_interfaces())
    )
    interface_info = await get_interface_info()

    device_name = (name or NAME).encode("utf-8")
    info = await make_service(
        endpoint_id=endpoint_id,
        visible=True,
        type_=Type.laptop,
        name=device_name,
        interface_info=interface_info,
    )
    services = [info]
    result: asyncio.Queue[ShareRequest] = asyncio.Queue()

    # Runs once at startup, before any transfer; not worth a thread hop.
    directory = (
        Path(download_dir).expanduser()  # noqa: ASYNC240
        if download_dir
        else default_download_dir()
    )
    directory.mkdir(parents=True, exist_ok=True)
    logger.debug("Receiving into %s", directory)

    create_task(
        _socket_server(
            result,
            interface_info=interface_info,
            endpoint_id=endpoint_id,
            download_dir=directory,
        )
    )
    create_task(_start_mdns_service(services))

    if bluetooth:
        # The transport Android actually uses off-network. RFCOMM below stays
        # registered because it publishes the SDP record, and because it is how
        # older senders may still connect, but this is the one that carries a
        # transfer when the phone has no network.
        await _le_l2cap_server(result, endpoint_id=endpoint_id, download_dir=directory)

        # BlueZ owns the RFCOMM socket and hands us a connected fd per client,
        # so it also allocates the channel and publishes the SDP record.
        def on_bluetooth_connection(fd: int, device: str) -> None:
            create_task(
                _handle_bluetooth_fd(
                    result, fd, device, endpoint_id=endpoint_id, download_dir=directory
                )
            )

        advertisement = await advertise_over_bluetooth(
            endpoint_id=endpoint_id,
            endpoint_info=bytes(make_n(visible=True, type=Type.laptop, name=device_name)),
            on_connection=on_bluetooth_connection,
        )
        if advertisement is not None:
            _advertisements.append(advertisement)

    while True:
        yield await result.get()


async def _start_mdns_service(services: list[AsyncServiceInfo]) -> None:
    runner = IPV4Runner()
    try:
        await runner.register_services(services)
    except asyncio.CancelledError:
        await runner.unregister_services(services)
