# type: ignore  # noqa: PGH003
"""Minimal org.bluez.Profile1, so BlueZ can hand us Quick Share connections.

Offering an RFCOMM service needs more than a listening socket: a sending device
looks the service up over SDP to learn which channel to use. Registering a
profile with BlueZ means it allocates the channel, publishes the SDP record and
passes us an already-connected file descriptor for each client, instead of us
binding a channel BlueZ does not know about and writing SDP XML by hand.
"""

from collections.abc import Callable
from logging import getLogger

from dbus_next.service import ServiceInterface, method

logger = getLogger(__name__)

__all__ = ("_QuickShareProfile",)

# ruff: disable[F722, N802, F821]


class _QuickShareProfile(ServiceInterface):
    """Receives incoming Bluetooth connections from BlueZ."""

    def __init__(self, on_connection: Callable[[int, str], None]) -> None:
        super().__init__("org.bluez.Profile1")
        self._on_connection = on_connection

    @method()
    def NewConnection(self, device: "o", fd: "h", fd_properties: "a{sv}") -> None:  # noqa: ARG002 - the signature is fixed by org.bluez.Profile1
        """Called by BlueZ with a connected RFCOMM socket.

        ``fd`` is already connected and authenticated; it just needs wrapping in
        a socket. dbus-next duplicates the descriptor for us, so this owns it.
        """
        logger.debug("Incoming Bluetooth connection from %s (fd %d)", device, fd)
        try:
            self._on_connection(fd, device)
        except Exception:
            # Raising here would return a D-Bus error to BlueZ and drop the
            # connection; log it and let the caller's own handling deal with it.
            logger.exception("Failed to take over Bluetooth connection from %s", device)

    @method()
    def RequestDisconnection(self, device: "o") -> None:
        logger.debug("BlueZ asked us to disconnect %s", device)

    @method()
    def Release(self) -> None:
        logger.debug("Quick Share profile released by BlueZ")


# ruff: enable[F722, N802, F821]
