import asyncio
import logging
from dataclasses import dataclass
from typing import Awaitable, Callable, Generic, Optional, TypeVar, override
from urllib.parse import urlparse

from asyncua import ua
from asyncua.ua.uaprotocol_hand import ReverseHello

from ..ua.ua_binary import header_from_binary, struct_from_binary
from .client import Client

_logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ReverseConnection:
    transport: asyncio.Transport
    hello_msg: ReverseHello


_T = TypeVar("_T")


@dataclass(frozen=True)
class LockedFuture(Generic[_T]):
    fut: asyncio.Future[_T]
    lock: asyncio.Lock


class ReverseConnectProtocol(asyncio.Protocol):
    """
    Handle reverse connect connection.
    Accept the first connection to succeed, or fail totally on first failed connection.
    Set `lfut` to with the transport of first succeeded connection or with and exception of first failed.
    """

    def __init__(self, lfut: LockedFuture[ReverseConnection]) -> None:
        """
        :param lfut: Future with a lock, given to each connection,
            to be filled with accepted reverse connection asyncio.Transport.
        """
        self.transport = None
        self.peer = None
        self.lfut = lfut
        self.receive_buffer = b""

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        self.transport = transport
        self.peer = transport.get_extra_info("peername")
        _logger.debug("Received connection from %s", self.peer)

    def data_received(self, data: bytes) -> None:
        if self.lfut.fut.done():
            self.disconnect()
            return

        buf = ua.utils.Buffer(data)
        try:
            header = header_from_binary(buf)
        except ua.utils.NotEnoughData:
            self.receive_buffer = data
            return

        if header.MessageType != ua.MessageType.ReverseHello:
            _logger.error(
                "Received invalid message instead of reverse hello from server %s: %s", self.peer, header.MessageType
            )
            asyncio.create_task(
                self._set_error(ua.UaError(f"Received invalid message instead of ReverseHello: {header.MessageType=}"))
            )
            self.disconnect()

        if len(buf) < header.body_size:
            self.receive_buffer = data
            return

        try:
            msg = struct_from_binary(ua.ReverseHello, buf)
            asyncio.create_task(self._set_reverse_connection(msg))
        except Exception as e:
            asyncio.create_task(self._set_error(e))
            self.disconnect()

    def connection_lost(self, exc: Optional[BaseException]) -> None:
        _logger.debug("reverse connection lost due to exception %s", exc)
        self.transport = None

    def disconnect(self) -> None:
        if self.transport:
            self.transport.close()

    async def _set_error(self, exception: Exception) -> None:
        async with self.lfut.lock:
            if self.lfut.fut.done():
                return
            self.lfut.fut.set_exception(exception)

    async def _set_reverse_connection(self, msg: ua.ReverseHello) -> None:
        if not self.transport:
            return
        async with self.lfut.lock:
            if self.lfut.fut.done():
                return
            payload = ReverseConnection(self.transport, msg)
            self.lfut.fut.set_result(payload)
            self.transport = None


async def wait_for_first_reverse_conn(host: str, port: int, *, timeout: float) -> ReverseConnection:
    """
    Spawn async server on `host` and `port` and return the socket (asyncio.Transport)
    of the first valid reverse connection alongside the received parameters.
    """
    lfut = LockedFuture(asyncio.get_running_loop().create_future(), asyncio.Lock())
    server = await asyncio.get_running_loop().create_server(
        lambda: ReverseConnectProtocol(lfut), host, port, reuse_address=True, start_serving=True
    )
    try:
        _logger.info("listening for reverse connection on %s:%s", host, port)
        payload = await asyncio.wait_for(lfut.fut, timeout)
    finally:
        server.close()

    return payload


class RCClient(Client):
    """
    Client subclass to connect to the OPC UA server with reverse connect mechanism instead of "normal" connect.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        server_verify_hook: Optional[Callable[[ua.ReverseHello], Awaitable[None]]] = None,
        connection_timeout: float = 30,
        timeout: float = 4,
        watchdog_intervall: float = 1.0,
        server_url: str = "",
    ) -> None:
        """
        :param url: url of the server.
            if you are unsure of url, write at least hostname
            and port and call get_endpoints
        :param timeout:
            Each request sent to the server expects an answer within this
            time. The timeout is specified in seconds.
        :param watchdog_intervall:
            The time between checking if the server is still alive. The timeout is specified in seconds.

        :param host: Host for client to listen on for reverse connect.
        :param port: Port for client to listen on for reverse connect.
        :param server_verify_hook: Hook to be called with received server parameters.
            If validation fails, the hook shall raise an exception.
        :param connection_timeout: The reverse connect connection is expected be received during this time.
            Specified in seconds.

        :param timeout: See Client.__init__().
        :param watchdog_intervall: See Client.__init__().
        :param server_url: URL of the server.

        Note that server URL is here for the case when server is still accessible for the client to connect and
        therefore the server certificate can be discovered instead of being passed to the client.
        In case that server certificate is not provided and server_url is missing/not accessible, the
        methods like `set_security` will fail.
        """
        super().__init__(server_url, timeout, watchdog_intervall)

        self.host = host
        self.port = port
        self.server_verify_hook = server_verify_hook
        self.connection_timeout = connection_timeout

    @override
    async def connect(self) -> None:
        _logger.info("reverse connect")
        conn = await wait_for_first_reverse_conn(self.host, self.port, timeout=self.connection_timeout)
        try:
            if self.server_verify_hook:
                await self.server_verify_hook(conn.hello_msg)
        except Exception:
            conn.transport.close()
            raise
        _logger.info("reverse connect with endpoint %s", conn.hello_msg.EndpointUrl)
        await self.uaclient.attach_socket(conn.transport)
        self._server_url = urlparse(conn.hello_msg.EndpointUrl)
        await self._perform_session_handshake()
