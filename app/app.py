import asyncio
from pathlib import Path

import aiohttp


async def fetch(session, url):
    async with session.get(url) as response:
        if response.status != 200:
            raise "Didn't work"  # TODO

        data = await response.text()

        files = []
        lines = data.splitlines()
        for line in lines:
            name, vtag = line.split(" ")

            # Process name
            is_dir = False
            if len(name) > 0 and name[-1] == "/":
                name = name[:-1]
                is_dir = True

            # Process vtag
            vtag = int(vtag)

            files.append({"name": name, "is_dir": is_dir, "vtag": vtag})

        return files


async def main():
    async with aiohttp.ClientSession() as session:
        remote = "http://127.0.0.1:8090"  # Must not end with a "/"
        remote_dir = remote + "/"
        local_dir = "local_root"

        local_dir = Path(local_dir)

        while True:
            # List of files in the remote root directory
            remote_files = await fetch(session, remote_dir)

            # List of files in the local root directory
            local_files = list(local_dir.iterdir())

            await asyncio.sleep(1)


try:
    asyncio.run(main())
except KeyboardInterrupt:
    pass
