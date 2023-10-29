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

from nacl.signing import SigningKey
import pytest

from secret_handshake import SHSClient, SHSServer

from .helpers import AsyncBuffer


class DummyCrypto:
    """Dummy crypto module, pretends everything is fine."""

    def verify_server_challenge(self, _):
        """Verify the server challenge"""

        return True

    def verify_challenge(self, _):
        """Verify the challenge data"""

        return True

    def verify_server_accept(self, _):
        """Verify server’s accept message"""
        return True

    def generate_challenge(self):
        """Generate authentication challenge"""

        return b"CHALLENGE"

    def generate_client_auth(self):
        """Generate client authentication data"""

        return b"AUTH"

    def verify_client_auth(self, _):
        """Verify client authentication data"""

        return True

    def generate_accept(self):
        """Generate an ACCEPT message"""

        return b"ACCEPT"

    def get_box_keys(self):
        """Get box keys"""

        return {
            "encrypt_key": b"x" * 32,
            "encrypt_nonce": b"x" * 32,
            "decrypt_key": b"x" * 32,
            "decrypt_nonce": b"x" * 32,
        }

    def clean(self):
        """Clean up internal data"""


def _dummy_boxstream(stream, **_):
    """Identity boxstream, no tansformation."""
    return stream


def _client_stream_mocker():
    reader = AsyncBuffer(b"xxx")
    writer = AsyncBuffer(b"xxx")

    async def _create_mock_streams(host, port):  # pylint: disable=unused-argument
        return reader, writer

    return reader, writer, _create_mock_streams


def _server_stream_mocker():
    reader = AsyncBuffer(b"xxx")
    writer = AsyncBuffer(b"xxx")

    async def _create_mock_server(cb, host, port):  # pylint: disable=unused-argument
        await cb(reader, writer)

    return reader, writer, _create_mock_server


@pytest.mark.asyncio
async def test_client(mocker):
    """Test the client"""

    reader, _, _create_mock_streams = _client_stream_mocker()
    mocker.patch("asyncio.open_connection", new=_create_mock_streams)
    mocker.patch("secret_handshake.boxstream.BoxStream", new=_dummy_boxstream)
    mocker.patch("secret_handshake.boxstream.UnboxStream", new=_dummy_boxstream)

    client = SHSClient("shop.local", 1111, SigningKey.generate(), os.urandom(32))
    client.crypto = DummyCrypto()

    await client.open()
    reader.append(b"TEST")
    assert (await client.read()) == b"TEST"
    client.disconnect()


@pytest.mark.asyncio
async def test_server(mocker):
    """Test the server"""

    resolve = Event()

    async def _on_connect(_):
        server.disconnect()
        resolve.set()

    _, _, _create_mock_server = _server_stream_mocker()
    mocker.patch("asyncio.start_server", new=_create_mock_server)
    mocker.patch("secret_handshake.boxstream.BoxStream", new=_dummy_boxstream)
    mocker.patch("secret_handshake.boxstream.UnboxStream", new=_dummy_boxstream)

    server = SHSServer("shop.local", 1111, SigningKey.generate(), os.urandom(32))
    server.crypto = DummyCrypto()

    server.on_connect(_on_connect)

    await server.listen()
    await wait_for(resolve.wait(), 5)
