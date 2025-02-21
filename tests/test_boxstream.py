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

"""Tests for the box stream"""

from asyncio import IncompleteReadError

from pytest_mock import MockerFixture

from secret_handshake.boxstream import HEADER_LENGTH, BoxStream, UnboxStream, get_stream_pair

from .helpers import AsyncBuffer, async_comprehend
from .test_crypto import CLIENT_ENCRYPT_KEY, CLIENT_ENCRYPT_NONCE

MESSAGE_1 = (
    b"\xcev\xedE\x06l\x02\x13\xc8\x17V\xfa\x8bZ?\x88B%O\xb0L\x9f\x8e\x8c0y\x1dv\xc0\xc9\xf6\x9d\xc2\xdf\xdb\xee\x9d"
)
MESSAGE_2 = b"\x141\xd63\x13d\xd1\xecZ\x9b\xd0\xd4\x03\xcdR?'\xaa.\x89I\x92I\xf9guL\xaa\x06?\xea\xca/}\x88*\xb2"
MESSAGE_3 = (
    b'\xcbYY\xf1\x0f\xa5O\x13r\xa6"\x15\xc5\x9d\r.*\x0b\x92\x10m\xa6(\x0c\x0c\xc61\x80j\x81)\x800\xed\xda\xad\xa1'
)
MESSAGE_CLOSED = b"\xb1\x14hU'\xb5M\xa6\"\x03\x9duy\xa1\xd4evW,\xdcE\x18\xe4+ C4\xe8h\x96\xed\xc5\x94\x80"


async def test_boxstream() -> None:
    """Test stream boxing"""

    buffer = AsyncBuffer()
    box_stream = BoxStream(buffer, CLIENT_ENCRYPT_KEY, CLIENT_ENCRYPT_NONCE)
    box_stream.write(b"foo")
    buffer.seek(0)
    assert await buffer.read() == MESSAGE_1

    pos = buffer.tell()
    box_stream.write(b"foo")
    buffer.seek(pos)
    assert await buffer.read() == MESSAGE_2

    pos = buffer.tell()
    box_stream.write(b"bar")
    buffer.seek(pos)
    assert await buffer.read() == MESSAGE_3

    pos = buffer.tell()
    box_stream.close()
    buffer.seek(pos)
    assert await buffer.read() == MESSAGE_CLOSED


async def test_unboxstream() -> None:
    """Test stream unboxing"""

    buffer = AsyncBuffer(MESSAGE_1 + MESSAGE_2 + MESSAGE_3 + MESSAGE_CLOSED)
    buffer.seek(0)

    unbox_stream = UnboxStream(buffer, CLIENT_ENCRYPT_KEY, CLIENT_ENCRYPT_NONCE)
    assert not unbox_stream.closed
    assert (await async_comprehend(unbox_stream)) == [b"foo", b"foo", b"bar"]
    assert unbox_stream.closed


async def test_unboxstream_header_read_error(mocker: MockerFixture) -> None:
    """Test that we can handle errors during header read"""

    buffer = AsyncBuffer()
    mocker.patch.object(buffer, "readexactly", side_effect=IncompleteReadError(b"", HEADER_LENGTH))

    unbox_stream = UnboxStream(buffer, CLIENT_ENCRYPT_KEY, CLIENT_ENCRYPT_NONCE)

    assert await unbox_stream.read() is None
    assert unbox_stream.closed is True


async def test_long_packets() -> None:
    """Test for receiving long packets"""

    data_size = 6 * 1024
    data = bytes(n % 256 for n in range(data_size))

    # box 6K buffer
    buffer = AsyncBuffer()
    box_stream = BoxStream(buffer, CLIENT_ENCRYPT_KEY, CLIENT_ENCRYPT_NONCE)
    box_stream.write(data)
    # the size overhead corresponds to the two packet headers
    assert buffer.tell() == data_size + (HEADER_LENGTH * 2)
    buffer.seek(0)

    # now let's unbox it and check whether it's OK
    unbox_stream = UnboxStream(buffer, CLIENT_ENCRYPT_KEY, CLIENT_ENCRYPT_NONCE)
    first_packet = await unbox_stream.read()
    assert first_packet == data[:4096]
    second_packet = await unbox_stream.read()
    assert second_packet == data[4096:]


def test_get_stream_pair() -> None:
    """Test the get_stream_pair() function"""

    read_buffer = AsyncBuffer()
    write_buffer = AsyncBuffer()

    read_stream, write_stream = get_stream_pair(
        read_buffer,
        write_buffer,
        decrypt_key=b"d" * 32,
        decrypt_nonce=b"dnonce",
        encrypt_key=b"e" * 32,
        encrypt_nonce=b"enonce",
    )

    assert isinstance(read_stream, UnboxStream)
    assert isinstance(write_stream, BoxStream)

    assert read_stream.key == b"d" * 32
    assert read_stream.nonce == b"dnonce"

    assert write_stream.key == b"e" * 32
    assert write_stream.nonce == b"enonce"
