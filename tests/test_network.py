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

"""Tests for the networking components"""

from asyncio import Event, wait_for
import os
from typing import Any, Awaitable, Callable, Tuple

from nacl.signing import SigningKey
import pytest
from pytest_mock import MockerFixture

from secret_handshake import SHSClient, SHSServer
from secret_handshake.boxstream import BoxStreamKeys

from .helpers import AsyncBuffer


class DummyCrypto:
    """Dummy crypto module, pretends everything is fine."""

    def verify_server_challenge(self, _: bytes) -> bool:
        """Verify the server challenge"""

        return True

    def verify_challenge(self, _: bytes) -> bool:
        """Verify the challenge data"""

        return True

    def verify_server_accept(self, _: bytes) -> bool:
        """Verify server’s accept message"""

        return True

    def generate_challenge(self) -> bytes:
        """Generate authentication challenge"""

        return b"CHALLENGE"

    def generate_client_auth(self) -> bytes:
        """Generate client authentication data"""

        return b"AUTH"

    def verify_client_auth(self, _: bytes) -> bool:
        """Verify client authentication data"""

        return True

    def generate_accept(self) -> bytes:
        """Generate an ACCEPT message"""

        return b"ACCEPT"

    def get_box_keys(self) -> BoxStreamKeys:
        """Get box keys"""

        return {
            "encrypt_key": b"x" * 32,
            "encrypt_nonce": b"x" * 32,
            "decrypt_key": b"x" * 32,
            "decrypt_nonce": b"x" * 32,
            "shared_secret": b"x" * 32,
        }

    def clean(self) -> None:
        """Clean up internal data"""


def _dummy_boxstream(stream: AsyncBuffer, **_: Any) -> AsyncBuffer:
    """Identity boxstream, no transformation."""

    return stream


def _client_stream_mocker() -> (
    Tuple[AsyncBuffer, AsyncBuffer, Callable[[str, int], Awaitable[Tuple[AsyncBuffer, AsyncBuffer]]]]
):
    reader = AsyncBuffer(b"xxx")
    writer = AsyncBuffer(b"xxx")

    async def _create_mock_streams(
        host: str, port: int  # pylint: disable=unused-argument
    ) -> Tuple[AsyncBuffer, AsyncBuffer]:
        return reader, writer

    return reader, writer, _create_mock_streams


def _server_stream_mocker() -> (
    Tuple[
        AsyncBuffer,
        AsyncBuffer,
        Callable[[Callable[[AsyncBuffer, AsyncBuffer], Awaitable[None]], str, int], Awaitable[None]],
    ]
):
    reader = AsyncBuffer(b"xxx")
    writer = AsyncBuffer(b"xxx")

    async def _create_mock_server(
        cb: Callable[[AsyncBuffer, AsyncBuffer], Awaitable[None]],
        host: str,  # pylint: disable=unused-argument
        port: int,  # pylint: disable=unused-argument
    ) -> None:
        await cb(reader, writer)

    return reader, writer, _create_mock_server


@pytest.mark.asyncio
async def test_client(mocker: MockerFixture) -> None:
    """Test the client"""

    reader, _, _create_mock_streams = _client_stream_mocker()
    mocker.patch("secret_handshake.network.open_connection", new=_create_mock_streams)
    mocker.patch("secret_handshake.boxstream.BoxStream", new=_dummy_boxstream)
    mocker.patch("secret_handshake.boxstream.UnboxStream", new=_dummy_boxstream)

    client = SHSClient("shop.local", 1111, SigningKey.generate(), os.urandom(32))
    client.crypto = DummyCrypto()  # type: ignore[assignment]

    await client.open()
    reader.append(b"TEST")
    assert (await client.read()) == b"TEST"
    client.disconnect()


@pytest.mark.asyncio
async def test_server(mocker: MockerFixture) -> None:
    """Test the server"""

    resolve = Event()

    async def _on_connect(_: Any) -> None:
        server.disconnect()
        resolve.set()

    _, _, _create_mock_server = _server_stream_mocker()
    mocker.patch("secret_handshake.network.start_server", new=_create_mock_server)
    mocker.patch("secret_handshake.boxstream.BoxStream", new=_dummy_boxstream)
    mocker.patch("secret_handshake.boxstream.UnboxStream", new=_dummy_boxstream)

    server = SHSServer("shop.local", 1111, SigningKey.generate(), os.urandom(32))
    server.crypto = DummyCrypto()  # type: ignore[assignment]

    server.on_connect(_on_connect)

    await server.listen()
    await wait_for(resolve.wait(), 5)
