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

"""Box stream utilities"""

from asyncio import IncompleteReadError, StreamReader, StreamWriter
import struct
from typing import Any, AsyncIterator, Optional, Tuple, TypedDict

from nacl.secret import SecretBox

from .util import inc_nonce, split_chunks

HEADER_LENGTH = 2 + 16 + 16
MAX_SEGMENT_SIZE = 4 * 1024
TERMINATION_HEADER = b"\x00" * 18


class BoxStreamKeys(TypedDict):
    """Dictionary to hold all box stream keys"""

    decrypt_key: bytes
    decrypt_nonce: bytes
    encrypt_key: bytes
    encrypt_nonce: bytes
    shared_secret: bytes


def get_stream_pair(  # pylint: disable=too-many-arguments
    reader: StreamReader,  # pylint: disable=unused-argument
    writer: StreamWriter,
    *,
    decrypt_key: bytes,
    decrypt_nonce: bytes,
    encrypt_key: bytes,
    encrypt_nonce: bytes,
    # We have kwargs here to devour any extra parameters we get, e.g. from the output of SHSCryptoBase.get_box_keys()
    **kwargs: Any,
) -> Tuple["UnboxStream", "BoxStream"]:
    """Create a new duplex box stream"""

    read_stream = UnboxStream(reader, key=decrypt_key, nonce=decrypt_nonce)
    write_stream = BoxStream(writer, key=encrypt_key, nonce=encrypt_nonce)

    return read_stream, write_stream


class UnboxStream:
    """Unboxing stream"""

    def __init__(self, reader: StreamReader, key: bytes, nonce: bytes):
        self.reader = reader
        self.key = key
        self.nonce = nonce
        self.closed = False

    async def read(self) -> Optional[bytes]:
        """Read data from the stream"""

        try:
            data = await self.reader.readexactly(HEADER_LENGTH)
        except IncompleteReadError:
            self.closed = True

            return None

        box = SecretBox(self.key)

        header = box.decrypt(data, self.nonce)

        if header == TERMINATION_HEADER:
            self.closed = True

            return None

        length = struct.unpack(">H", header[:2])[0]
        mac = header[2:]

        data = await self.reader.readexactly(length)

        body = box.decrypt(mac + data, inc_nonce(self.nonce))

        self.nonce = inc_nonce(inc_nonce(self.nonce))

        return body

    def __aiter__(self) -> AsyncIterator[bytes]:
        return self

    async def __anext__(self) -> bytes:
        data = await self.read()

        if data is None:
            raise StopAsyncIteration()

        return data


class BoxStream:
    """Box stream"""

    def __init__(self, writer: StreamWriter, key: bytes, nonce: bytes):
        self.writer = writer
        self.key = key
        self.box = SecretBox(self.key)
        self.nonce = nonce

    def write(self, data: bytes) -> None:
        """Write data to the box stream"""

        for chunk in split_chunks(data, MAX_SEGMENT_SIZE):
            body = self.box.encrypt(bytes(chunk), inc_nonce(self.nonce))[24:]
            header = struct.pack(">H", len(body) - 16) + body[:16]

            hdrbox = self.box.encrypt(header, self.nonce)[24:]
            self.writer.write(hdrbox)

            self.nonce = inc_nonce(inc_nonce(self.nonce))
            self.writer.write(body[16:])

    def close(self) -> None:
        """Close the box stream"""

        self.writer.write(self.box.encrypt(b"\x00" * 18, self.nonce)[24:])
