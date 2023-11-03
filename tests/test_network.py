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

"""Tests for the networking components"""

from asyncio import Event, wait_for
import os
from typing import Any, Awaitable, Callable, Literal, Tuple

from nacl.signing import SigningKey
import pytest
from pytest_mock import MockerFixture

from secret_handshake import SHSClient, SHSServer
from secret_handshake.boxstream import BoxStreamKeys
from secret_handshake.network import SHSClientException, SHSDuplexStream

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


def test_duplex_write(mocker: MockerFixture) -> None:
    """Test the writing capabilities of the duplex stream"""

    d_stream = SHSDuplexStream()
    d_stream.write_stream = mocker.AsyncMock()
    d_stream.write(b"thing")

    assert d_stream.write_stream

    d_stream.write_stream.write.assert_called_once_with(b"thing")  # type: ignore[attr-defined]


def test_duplex_close_no_write_stream() -> None:
    """Test if SHSDuplexStream’s close method doesn’t fail if there is no write stream"""

    d_stream = SHSDuplexStream()
    assert d_stream.write_stream is None
    d_stream.close()

    # We cannot really do assertions here. If there is not set (it is None), the above call would fail


def test_duplex_stream_aiter() -> None:
    """Test if the __aiter__ method of SHSDuplexStream returns the stream itself"""

    d_stream = SHSDuplexStream()
    assert d_stream.__aiter__() is d_stream  # pylint: disable=unnecessary-dunder-call


async def test_duplex_stream_anext(mocker: MockerFixture) -> None:
    """Test if the __anext__ method of SHSDuplexStream reads from the stream"""

    d_stream = SHSDuplexStream()
    mocker.patch.object(d_stream, "read", mocker.AsyncMock(return_value=b"test"))

    assert await d_stream.__anext__() == b"test"  # pylint: disable=unnecessary-dunder-call


async def test_duplex_stream_anext_eof(mocker: MockerFixture) -> None:
    """Test if SHSDuplexStream.__anext__ breaks iteration if there’s no data to read"""

    d_stream = SHSDuplexStream()
    mocker.patch.object(d_stream, "read", mocker.AsyncMock(return_value=None))

    with pytest.raises(StopAsyncIteration):
        assert await d_stream.__anext__()  # pylint: disable=unnecessary-dunder-call


@pytest.mark.parametrize("fail_type", ("verify_challenge", "verify_auth"))
async def test_server_fail_handshake(
    fail_type: Literal["verify_challenge", "verify_auth"], mocker: MockerFixture
) -> None:
    """Test if a failing handshake results in an SHSClientException"""

    server = SHSServer("127.0.0.1", 8754, SigningKey.generate())

    if fail_type == "verify_challenge":
        expected_error = "Client challenge is not valid"
    elif fail_type == "verify_auth":  # pragma: no branch
        expected_error = "Client auth is not valid"

    mocker.patch.object(server.crypto, "verify_challenge", return_value=fail_type != "verify_challenge")
    mocker.patch.object(server.crypto, "verify_client_auth", return_value=fail_type != "verify_auth")

    with pytest.raises(SHSClientException) as ctx:
        await server._handshake(AsyncBuffer(b"d" * 64), AsyncBuffer())  # pylint: disable=protected-access

    assert str(ctx.value) == expected_error


async def test_server_no_connect_callback(mocker: MockerFixture) -> None:
    """Test if SHSServer.handle_connection works without an on_connect callback"""

    server = SHSServer("127.0.0.1", 7429, SigningKey.generate())
    mocker.patch.object(server, "_handshake", return_value=None)
    mocker.patch.object(
        server.crypto,
        "get_box_keys",
        return_value={
            "decrypt_key": b"d" * 32,
            "decrypt_nonce": b"dnonce",
            "encrypt_key": b"e" * 32,
            "encrypt_nonce": b"enonce",
        },
    )

    await server.handle_connection(AsyncBuffer(), AsyncBuffer())

    # No assertion here.  We should get here without a problem


@pytest.mark.parametrize("fail_type", ("verify_challenge", "verify_accept"))
async def test_client_fail_handshake(
    fail_type: Literal["verify_challenge", "verify_accept"], mocker: MockerFixture
) -> None:
    """Test if a failing handshake results in an SHSClientException"""

    client = SHSClient("127.0.0.1", 8754, SigningKey.generate(), b"s" * 32)

    if fail_type == "verify_challenge":
        expected_error = "Server challenge is not valid"
    elif fail_type == "verify_accept":  # pragma: no branch
        expected_error = "Server accept is not valid"

    mocker.patch.object(client.crypto, "verify_server_challenge", return_value=fail_type != "verify_challenge")
    mocker.patch.object(client.crypto, "verify_server_accept", return_value=fail_type != "verify_accept")
    mocker.patch.object(client.crypto, "generate_client_auth", return_value=b"ca" * 16)

    with pytest.raises(SHSClientException) as ctx:
        await client._handshake(AsyncBuffer(b"d" * 64), AsyncBuffer())  # pylint: disable=protected-access

    assert str(ctx.value) == expected_error


@pytest.mark.parametrize("with_callback", (True, False))
async def test_client_open(with_callback: bool, mocker: MockerFixture) -> None:
    """Test if SHSServer.handle_connection works with and without an on_connect callback"""

    client = SHSClient("127.0.0.1", 7429, SigningKey.generate(), SigningKey.generate().verify_key.encode())

    mocker.patch("secret_handshake.network.open_connection", return_value=(AsyncBuffer(), AsyncBuffer()))
    mocker.patch.object(client, "_handshake", return_value=None)
    mocker.patch.object(
        client.crypto,
        "get_box_keys",
        return_value={
            "decrypt_key": b"d" * 32,
            "decrypt_nonce": b"dnonce",
            "encrypt_key": b"e" * 32,
            "encrypt_nonce": b"enonce",
        },
    )

    if with_callback:
        callback = mocker.AsyncMock()
        client.on_connect(callback)

    await client.open()

    if with_callback:
        callback.assert_awaited_once_with(client)
