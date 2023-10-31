# SPDX-License-Identifier: MIT
#
# Copyright (c) 2017 PySecretHandshake contributors (see AUTHORS for more details)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Networking functionality"""

from asyncio import StreamReader, StreamWriter, ensure_future, open_connection, start_server
from typing import AsyncIterator, Awaitable, Callable, List, Optional

from nacl.public import PrivateKey
from nacl.signing import SigningKey
from typing_extensions import Self

from .boxstream import BoxStream, UnboxStream, get_stream_pair
from .crypto import SHSClientCrypto, SHSCryptoBase, SHSServerCrypto


class SHSClientException(Exception):
    """Base exception class for client errors"""


class SHSDuplexStream:
    """SHS duplex stream"""

    def __init__(self) -> None:
        self.write_stream: Optional[BoxStream] = None
        self.read_stream: Optional[UnboxStream] = None
        self.is_connected = False

    def write(self, data: bytes) -> None:
        """Write data to the write stream"""

        assert self.write_stream

        self.write_stream.write(data)

    async def read(self) -> Optional[bytes]:
        """Read data from the read stream"""

        assert self.read_stream

        return await self.read_stream.read()

    def close(self) -> None:
        """Close the duplex stream"""

        if self.write_stream:
            self.write_stream.close()

        self.is_connected = False

    def __aiter__(self) -> AsyncIterator[bytes]:
        return self

    async def __anext__(self) -> bytes:
        msg = await self.read()

        if msg is None:
            raise StopAsyncIteration()

        return msg


class SHSEndpoint:
    """SHS endpoint"""

    def __init__(self) -> None:
        self._on_connect: Optional[Callable[[SHSDuplexStream], Awaitable[None]]] = None
        self.crypto: Optional[SHSCryptoBase] = None

    def on_connect(self, cb: Callable[[SHSDuplexStream], Awaitable[None]]) -> None:
        """Set the function to be called when a new connection arrives"""

        self._on_connect = cb

    def disconnect(self) -> None:
        """Disconnect the endpoint"""

        raise NotImplementedError


class SHSServer(SHSEndpoint):
    """SHS server"""

    def __init__(self, host: str, port: int, server_kp: SigningKey, application_key: Optional[bytes] = None):
        super().__init__()
        self.host = host
        self.port = port
        self.crypto: SHSServerCrypto = SHSServerCrypto(server_kp, application_key=application_key)
        self.connections: List[SHSServerConnection] = []

    async def _handshake(self, reader: StreamReader, writer: StreamWriter) -> None:
        assert self.crypto

        data = await reader.readexactly(64)

        if not self.crypto.verify_challenge(data):
            raise SHSClientException("Client challenge is not valid")

        writer.write(self.crypto.generate_challenge())

        data = await reader.readexactly(112)

        if not self.crypto.verify_client_auth(data):
            raise SHSClientException("Client auth is not valid")

        writer.write(self.crypto.generate_accept())

    async def handle_connection(self, reader: StreamReader, writer: StreamWriter) -> None:
        """Handle incoming connections"""

        assert self.crypto

        self.crypto.clean()
        await self._handshake(reader, writer)
        keys = self.crypto.get_box_keys()
        self.crypto.clean()

        conn = SHSServerConnection.from_byte_streams(reader, writer, **keys)
        self.connections.append(conn)

        if self._on_connect:
            ensure_future(self._on_connect(conn))

    async def listen(self) -> None:
        """Listen for connections"""

        await start_server(self.handle_connection, self.host, self.port)

    def disconnect(self) -> None:
        for connection in self.connections:
            connection.close()


class SHSServerConnection(SHSDuplexStream):
    """SHS server connection"""

    def __init__(self, read_stream: UnboxStream, write_stream: BoxStream):
        super().__init__()

        self.read_stream = read_stream
        self.write_stream = write_stream

    @classmethod
    def from_byte_streams(cls, reader: StreamReader, writer: StreamWriter, **keys: bytes) -> Self:
        """Create a server connection from an existing byte stream"""

        box_reader, box_writer = get_stream_pair(reader, writer, **keys)

        return cls(box_reader, box_writer)


class SHSClient(SHSDuplexStream, SHSEndpoint):
    """SHS client"""

    def __init__(  # pylint: disable=too-many-arguments
        self,
        host: str,
        port: int,
        client_kp: SigningKey,
        server_pub_key: bytes,
        ephemeral_key: Optional[PrivateKey] = None,
        application_key: Optional[bytes] = None,
    ):
        SHSDuplexStream.__init__(self)
        SHSEndpoint.__init__(self)
        self.host = host
        self.port = port
        self.writer: Optional[StreamWriter] = None
        self.crypto: SHSClientCrypto = SHSClientCrypto(
            client_kp,
            server_pub_key,
            ephemeral_key=ephemeral_key or PrivateKey.generate(),
            application_key=application_key,
        )

    async def _handshake(self, reader: StreamReader, writer: StreamWriter) -> None:
        writer.write(self.crypto.generate_challenge())

        data = await reader.readexactly(64)

        if not self.crypto.verify_server_challenge(data):
            raise SHSClientException("Server challenge is not valid")

        writer.write(self.crypto.generate_client_auth())
        data = await reader.readexactly(80)

        if not self.crypto.verify_server_accept(data):
            raise SHSClientException("Server accept is not valid")

    async def open(self) -> None:
        """Open the TCP connection"""

        reader, writer = await open_connection(self.host, self.port)
        await self._handshake(reader, writer)

        keys = self.crypto.get_box_keys()
        self.crypto.clean()

        self.read_stream, self.write_stream = get_stream_pair(reader, writer, **keys)
        self.writer = writer
        self.is_connected = True

        if self._on_connect:
            await self._on_connect(self)

    def disconnect(self) -> None:
        self.close()
