"""Example SHS client"""

import os
from asyncio import get_event_loop
from base64 import b64decode

import yaml
from nacl.signing import SigningKey

from secret_handshake import SHSClient

with open(os.path.expanduser("~/.ssb/secret"), encoding="utf-8") as f:
    config = yaml.safe_load(f)


async def main():
    """Main function to run"""

    server_pub_key = b64decode(config["public"][:-8])
    client = SHSClient("localhost", 8008, SigningKey.generate(), server_pub_key)
    await client.open()

    async for msg in client:
        print(msg)


if __name__ == "__main__":
    loop = get_event_loop()
    loop.run_until_complete(main())
    loop.close()
