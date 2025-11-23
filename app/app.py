import asyncio
from pathlib import Path

import aiohttp
from watchfiles import Change, awatch

local_root = "."
remote_root = f"http://127.0.0.1:8090/"


async def main():
    async for changes in awatch(local_root):
        for change_type, filepath in changes:
            await process_change(change_type, filepath)


async def process_change(change_type, filepath):
    if change_type == Change.added:
        await process_change_added(filepath)
    elif change_type == Change.modified:
        await process_change_modified(filepath)
    elif change_type == Change.deleted:
        await process_change_deleted(filepath)
    else:
        raise "Unexpected change type"


def make_relative_path(root, target):
    root = Path(root).resolve()
    target = Path(target).resolve()
    return str(target.relative_to(root))


def endpoint_from_local_path(local_target):
    relative_path = make_relative_path(local_root, local_target)
    remote_target = remote_root + relative_path

    assert remote_target[-1] != "/"
    if Path(local_target).is_dir():
        remote_target += "/"

    return remote_target


async def process_change_added(local_target):
    async with aiohttp.ClientSession() as session:
        # Determine the endpoint the file should be
        # uploaded to.
        remote_target = endpoint_from_local_path(local_target)

        # Read its contents
        with open(local_target, "rb") as f:
            data = f.read()

        # Upload
        async with session.put(remote_target, data=data) as response:
            pass  # TODO


async def process_change_modified(local_target):
    async with aiohttp.ClientSession() as session:
        # Determine the endpoint the file should be
        # uploaded to.
        remote_target = endpoint_from_local_path(local_target)

        # Read its contents
        with open(local_target, "rb") as f:
            data = f.read()

        # Upload
        async with session.put(remote_target, data=data) as response:
            pass  # TODO


async def process_change_deleted(local_target):
    async with aiohttp.ClientSession() as session:
        # Determine the endpoint that should be deleted
        remote_target = endpoint_from_local_path(local_target)

        # Delete
        async with session.delete(remote_target) as response:
            pass  # TODO


try:
    asyncio.run(main())
except KeyboardInterrupt:
    pass
