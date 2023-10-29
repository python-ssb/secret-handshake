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

import asyncio

from .boxstream import get_stream_pair
from .crypto import SHSClientCrypto, SHSServerCrypto


class SHSClientException(Exception):
    """Base exception class for client errors"""


class SHSDuplexStream:
    """SHS duplex stream"""

    def __init__(self):
        self.write_stream = None
        self.read_stream = None
        self.is_connected = False

    def write(self, data):
        """Write data to the write stream"""

        self.write_stream.write(data)

    async def read(self):
        """Read data from the read stream"""

        return await self.read_stream.read()

    def close(self):
        """Close the duplex stream"""

        self.write_stream.close()
        self.read_stream.close()
        self.is_connected = False

    def __aiter__(self):
        return self

    async def __anext__(self):
        msg = await self.read()

        if msg is None:
            raise StopAsyncIteration()

        return msg


class SHSEndpoint:
    """SHS endpoint"""

    def __init__(self):
        self._on_connect = None
        self.crypto = None

    def on_connect(self, cb):
        """Set the function to be called when a new connection arrives"""
        self._on_connect = cb

    def disconnect(self):
        """Disconnect the endpoint"""
        raise NotImplementedError


class SHSServer(SHSEndpoint):
    """SHS server"""

    def __init__(self, host, port, server_kp, application_key=None):
        super().__init__()
        self.host = host
        self.port = port
        self.crypto = SHSServerCrypto(server_kp, application_key=application_key)
        self.connections = []

    async def _handshake(self, reader, writer):
        data = await reader.readexactly(64)
        if not self.crypto.verify_challenge(data):
            raise SHSClientException("Client challenge is not valid")

        writer.write(self.crypto.generate_challenge())

        data = await reader.readexactly(112)
        if not self.crypto.verify_client_auth(data):
            raise SHSClientException("Client auth is not valid")

        writer.write(self.crypto.generate_accept())

    async def handle_connection(self, reader, writer):
        """Handle incoming connections"""

        self.crypto.clean()
        await self._handshake(reader, writer)
        keys = self.crypto.get_box_keys()
        self.crypto.clean()

        conn = SHSServerConnection.from_byte_streams(reader, writer, **keys)
        self.connections.append(conn)

        if self._on_connect:
            asyncio.ensure_future(self._on_connect(conn))

    async def listen(self):
        """Listen for connections"""

        await asyncio.start_server(self.handle_connection, self.host, self.port)

    def disconnect(self):
        for connection in self.connections:
            connection.close()


class SHSServerConnection(SHSDuplexStream):
    """SHS server connection"""

    def __init__(self, read_stream, write_stream):
        super().__init__()
        self.read_stream = read_stream
        self.write_stream = write_stream

    @classmethod
    def from_byte_streams(cls, reader, writer, **keys):
        """Create a server connection from an existing byte stream"""

        reader, writer = get_stream_pair(reader, writer, **keys)

        return cls(reader, writer)


class SHSClient(SHSDuplexStream, SHSEndpoint):
    """SHS client"""

    def __init__(  # pylint: disable=too-many-arguments
        self, host, port, client_kp, server_pub_key, ephemeral_key=None, application_key=None
    ):
        SHSDuplexStream.__init__(self)
        SHSEndpoint.__init__(self)
        self.host = host
        self.port = port
        self.writer = None
        self.crypto = SHSClientCrypto(
            client_kp, server_pub_key, ephemeral_key=ephemeral_key, application_key=application_key
        )

    async def _handshake(self, reader, writer):
        writer.write(self.crypto.generate_challenge())

        data = await reader.readexactly(64)
        if not self.crypto.verify_server_challenge(data):
            raise SHSClientException("Server challenge is not valid")

        writer.write(self.crypto.generate_client_auth())

        data = await reader.readexactly(80)
        if not self.crypto.verify_server_accept(data):
            raise SHSClientException("Server accept is not valid")

    async def open(self):
        """Open the TCP connection"""

        reader, writer = await asyncio.open_connection(self.host, self.port)
        await self._handshake(reader, writer)

        keys = self.crypto.get_box_keys()
        self.crypto.clean()

        self.read_stream, self.write_stream = get_stream_pair(reader, writer, **keys)
        self.writer = writer
        self.is_connected = True

        if self._on_connect:
            await self._on_connect()

    def disconnect(self):
        self.close()
