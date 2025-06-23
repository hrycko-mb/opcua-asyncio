import asyncio
from dataclasses import dataclass
from datetime import timedelta
import socket

from asyncua import ua
from asyncua.ua.uaprotocol_hand import ReverseHello

from ..ua.ua_binary import header_from_binary, struct_from_binary


@dataclass
class ReverseConnection:
    socket: socket.socket
    hello_msg: ReverseHello


class ReverseConnectProtocol(asyncio.Protocol):
    def __init__(self, fut: asyncio.Future[ReverseConnection]) -> None:
        self.transport = None
        self.fut = fut
        self.receive_buffer = b""

    def connection_made(self, transport):
        self.transport = transport
        peer = transport.get_extra_info("peername")
        print(f"received connection from {peer!r}")

    def data_received(self, data: bytes):
        if self.fut.done():
            self.disconnect()
            return

        print(f"received {data!r}")
        buf = ua.utils.Buffer(data)
        try:
            header = header_from_binary(buf)
        except ua.utils.NotEnoughData:
            self.receive_buffer = data
            return
        if len(buf) < header.body_size:
            self.receive_buffer = data
            return

        if header.MessageType != ua.MessageType.ReverseHello:
            self.disconnect()
            raise ua.UaError("Expected only Reverse Hello message")

        msg = struct_from_binary(ua.ReverseHello, buf)
        print(msg)
        if self.transport:
            payload = ReverseConnection(self.transport.get_extra_info("socket").dup(), msg)
            self.fut.set_result(payload)
        self.disconnect()

    def connection_lost(self, exc: BaseException | None):
        print(f"connection lost due to: {exc}")
        self.transport = None

    def disconnect(self) -> None:
        if self.transport:
            self.transport.close()


async def wait_for_first_connection(host: str, port: int, timeout: timedelta) -> ReverseConnection:
    fut = asyncio.Future()
    async with await asyncio.get_running_loop().create_server(
        lambda: ReverseConnectProtocol(fut), host, port, reuse_address=True, start_serving=True
    ):
        print(f"listening on {host!r}:{port}")
        payload = await asyncio.wait_for(fut, timeout.total_seconds())

    return payload
