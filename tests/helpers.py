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

"""Helper utilities for testing"""

from asyncio import StreamReader, StreamWriter
from io import BytesIO
from typing import AsyncIterable, List, Optional, TypeVar

T = TypeVar("T")


class AsyncBuffer(BytesIO, StreamReader, StreamWriter):  # type: ignore[misc]
    """Just a BytesIO with an async read method."""

    async def read(  # type: ignore[override] # pylint: disable=invalid-overridden-method
        self, n: Optional[int] = None
    ) -> Optional[bytes]:
        v = super().read(n)

        return v

    readexactly = read  # type: ignore[assignment]

    def append(self, data: bytes) -> None:
        """Append data to the buffer without changing the current position."""

        pos = self.tell()
        self.write(data)
        self.seek(pos)


async def async_comprehend(generator: AsyncIterable[T]) -> List[T]:
    """Emulate ``[elem async for elem in generator]``."""

    results = []

    async for msg in generator:
        results.append(msg)

    return results
