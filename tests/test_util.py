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

"""Tests for utility functions"""

import math
from types import GeneratorType
from typing import List, Sequence, TypeVar

import pytest

from secret_handshake.util import bytes_to_long, inc_nonce, long_to_bytes, split_chunks

T = TypeVar("T")


@pytest.mark.parametrize(
    "in_,out",
    (
        (b"\x00\x00\x00\x00", b"\x00" * 23 + b"\x01"),
        (b"\xff" * 24, b"\x00" * 24),
    ),
)
def test_inc_nonce(in_: bytes, out: bytes) -> None:
    """Test the inc_nonce function"""

    result = inc_nonce(in_)

    assert len(result) == 24
    assert result == out


def test_split_chunks_is_generator() -> None:
    """Test if split_chunks returns a generator"""

    assert isinstance(split_chunks([], 1), GeneratorType)


@pytest.mark.parametrize("size", (-123, -1, 0))
def test_nonpositive_chunk_size(size: int) -> None:
    """Test if split_chunks() with non-positive chunk sizes raise an error"""

    with pytest.raises(ValueError) as ctx:
        list(split_chunks(b"", size))

    assert str(ctx.value) == "chunk_size must be greater than zero"


@pytest.mark.parametrize(
    "in_,chunksize,out",
    (
        (b"asdfg", 2, [b"as", b"df", b"g"]),
        (b"asdfgh", 3, [b"asd", b"fgh"]),
    ),
)
def test_split_chunks(in_: Sequence[T], chunksize: int, out: List[Sequence[T]]) -> None:
    """Test if split_chunks splits the input into equal chunks"""

    assert list(split_chunks(in_, chunksize)) == out


@pytest.mark.parametrize(
    "in_,out",
    (
        (0, b"\x00"),
        (1, b"\x01"),
        (4278255360, b"\xff\x00\xff\x00"),
        (65536, b"\x01\x00\x00"),
        (4546694913, b"\x01\x0f\x01\x0f\x01"),
    ),
)
@pytest.mark.parametrize("blocksize", (0, 4, 6))
def test_long_to_bytes(in_: int, out: bytes, blocksize: int) -> None:
    """Test long_to_bytes"""

    result = long_to_bytes(in_, blocksize=blocksize)

    if blocksize:
        block_count = math.ceil(len(out) / blocksize)
    else:
        block_count = 1

    padding = b"\x00" * blocksize * block_count
    expected = (padding + out)[-(blocksize * block_count) :]

    if blocksize:
        assert not len(result) % blocksize

    assert result == expected


@pytest.mark.parametrize(
    "in_,out",
    (
        (b"\x00\x00\x00\x00", 0),
        (b"\x00\x00\x00\x01", 1),
        (b"\xff\x00\xff\x00", 4278255360),
        (b"\x01\x00\x00", 65536),
        (b"\x01\x0f\x01\x0f\x01", 4546694913),
    ),
)
def test_bytes_to_long(in_: bytes, out: int) -> None:
    """Test bytes_to_long"""

    assert bytes_to_long(in_) == out
