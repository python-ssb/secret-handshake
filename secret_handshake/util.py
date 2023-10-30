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

"""Utility functions"""

import struct
from typing import Generator, Sequence, TypeVar

NONCE_SIZE = 24
MAX_NONCE = 8 * NONCE_SIZE
T = TypeVar("T")


def inc_nonce(nonce: bytes) -> bytes:
    """Increment nonce"""

    num = bytes_to_long(nonce) + 1

    if num > 2**MAX_NONCE:
        num = 0

    bnum = long_to_bytes(num)
    bnum = b"\x00" * (NONCE_SIZE - len(bnum)) + bnum

    return bnum


def split_chunks(seq: Sequence[T], n: int) -> Generator[Sequence[T], None, None]:
    """Split sequence in equal-sized chunks.

    The last chunk is not padded."""

    while seq:
        yield seq[:n]
        seq = seq[n:]


# Stolen from PyCypto (Public Domain)
def b(s: str) -> bytes:
    """Shorthand for s.encode("latin-1")"""

    return s.encode("latin-1")  # utf-8 would cause some side-effects we don't want


def long_to_bytes(n: int, blocksize: int = 0) -> bytes:
    """Convert a long integer to a byte string.

    If optional ``blocksize`` is given and greater than zero, pad the front of the byte string with binary zeros so
    that the length is a multiple of blocksize.
    """

    # after much testing, this algorithm was deemed to be the fastest
    s = b("")
    pack = struct.pack

    while n > 0:
        s = pack(">I", n & 0xFFFFFFFF) + s
        n = n >> 32

    # strip off leading zeros
    for i, c in enumerate(s):
        if c != b("\000")[0]:
            break
    else:
        # only happens when n == 0
        s = b("\000")
        i = 0

    s = s[i:]

    # add back some pad bytes.  this could be done more efficiently w.r.t. the
    # de-padding being done above, but sigh...
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * b("\000") + s

    return s


def bytes_to_long(s: bytes) -> int:
    """Convert a byte string to a long integer.

    This is (essentially) the inverse of ``long_to_bytes()``.
    """

    acc = 0
    unpack = struct.unpack
    length = len(s)

    if length % 4:
        extra = 4 - length % 4
        s = b("\000") * extra + s
        length = length + extra

    for i in range(0, length, 4):
        acc = (acc << 32) + unpack(">I", s[i : i + 4])[0]

    return acc
