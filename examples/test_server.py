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

"""Example SHS server"""

from asyncio import get_event_loop
from base64 import b64decode
import os

from nacl.signing import SigningKey
import yaml

from secret_handshake import SHSServer
from secret_handshake.network import SHSDuplexStream

with open(os.path.expanduser("~/.ssb/secret"), encoding="utf-8") as f:
    config = yaml.safe_load(f)


async def _on_connect(conn: SHSDuplexStream) -> None:
    async for msg in conn:
        print(msg)


async def main() -> None:
    """Main function to run"""

    server_keypair = SigningKey(b64decode(config["private"][:-8])[:32])
    server = SHSServer("localhost", 8008, server_keypair)
    server.on_connect(_on_connect)
    await server.listen()


if __name__ == "__main__":
    loop = get_event_loop()
    loop.run_until_complete(main())
    loop.run_forever()
    loop.close()
