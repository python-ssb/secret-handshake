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
