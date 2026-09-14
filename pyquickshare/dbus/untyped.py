# type: ignore  # noqa: PGH003
"""org.bluez.LEAdvertisement1 implementations.

BlueZ takes advertisements as exported D-Bus objects rather than as a call, so
each kind of advertisement is a small ServiceInterface it reads properties from.
"""

from logging import getLogger

from dbus_next.constants import PropertyAccess
from dbus_next.service import ServiceInterface, dbus_property, method
from dbus_next.signature import Variant

SERVICE_UUID = "0000fe2c-0000-1000-8000-00805f9b34fb"
"""Fast Init. Nudges nearby devices into advertising themselves."""

RECEIVE_SERVICE_UUID = "0000fef3-0000-1000-8000-00805f9b34fb"
"""Quick Share presence. What a sender scans for to find receivers."""

logger = getLogger(__name__)

__all__ = ("_FastInitAdvertisement", "_ReceiveAdvertisement")

# ruff: disable[F722, N802, F821]


class _FastInitAdvertisement(ServiceInterface):
    """Minimal org.bluez.LEAdvertisement1 implementation."""

    def __init__(self, payload: bytes) -> None:
        super().__init__("org.bluez.LEAdvertisement1")
        self._payload = payload
        self._txpower = 0

    @dbus_property(access=PropertyAccess.READ)
    def Type(self) -> "s":  # type: ignore[override]
        return "broadcast"

    @dbus_property(access=PropertyAccess.READ)
    def ServiceData(self) -> "a{sv}":
        return {SERVICE_UUID: Variant("ay", self._payload)}

    @dbus_property(access=PropertyAccess.READWRITE)
    def TxPower(self) -> "n":  # type: ignore[override]
        return self._txpower

    @TxPower.setter
    def TxPower(self, value: "n") -> None:  # type: ignore[override]
        self._txpower = value

    @method()
    async def Release(self) -> None:
        # This used to call bluetooth.debug, a name that does not exist in this
        # module, so BlueZ releasing the advertisement raised NameError instead
        # of logging.
        logger.debug("Fast Init advertisement released by BlueZ")


class _ReceiveAdvertisement(ServiceInterface):
    """Advertises this machine as a Quick Share receiver.

    Android finds receivers by scanning for service data under
    ``0000fef3``. Without this a device is visible in the phone's Bluetooth
    list, because the Classic adapter name is set, but never appears in Quick
    Share itself.
    """

    def __init__(self, payload: bytes) -> None:
        super().__init__("org.bluez.LEAdvertisement1")
        self._payload = payload
        self._txpower = 0

    @dbus_property(access=PropertyAccess.READ)
    def Type(self) -> "s":  # type: ignore[override]
        return "peripheral"

    @dbus_property(access=PropertyAccess.READ)
    def ServiceUUIDs(self) -> "as":
        return [RECEIVE_SERVICE_UUID]

    @dbus_property(access=PropertyAccess.READ)
    def ServiceData(self) -> "a{sv}":
        return {RECEIVE_SERVICE_UUID: Variant("ay", self._payload)}

    @dbus_property(access=PropertyAccess.READ)
    def Discoverable(self) -> "b":  # type: ignore[override]
        return True

    @dbus_property(access=PropertyAccess.READ)
    def IncludeTxPower(self) -> "b":  # type: ignore[override]
        return False

    @dbus_property(access=PropertyAccess.READWRITE)
    def TxPower(self) -> "n":  # type: ignore[override]
        # BlueZ reads this even though it is optional, and dbus-next answers a
        # missing property with a D-Bus error rather than silence, so leaving it
        # out puts an UNKNOWN_PROPERTY error in the log on every registration.
        return self._txpower

    @TxPower.setter
    def TxPower(self, value: "n") -> None:  # type: ignore[override]
        self._txpower = value

    @method()
    async def Release(self) -> None:
        logger.debug("Quick Share receive advertisement released by BlueZ")


# ruff: enable[F722, N802, F821]
