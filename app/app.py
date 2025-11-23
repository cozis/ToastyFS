import asyncio
import logging
from pathlib import Path

from aiohttp import (
    ClientSession,
    TraceConfig,
    TraceRequestEndParams,
    TraceRequestStartParams,
)
from watchfiles import Change, awatch

local_root = "."
remote_root = f"http://127.0.0.1:8090/"

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",  # No timestamp prefix for curl-like output
)
logger = logging.getLogger(__name__)


async def on_request_start(session, context, params: TraceRequestStartParams):
    logger.info(f"> {params.method} {params.url.path_qs} HTTP/1.1")
    logger.info(f"> Host: {params.url.host}")
    for name, value in params.headers.items():
        logger.info(f"> {name}: {value}")
    logger.info(">")


async def on_request_end(session, context, params: TraceRequestEndParams):
    response = params.response
    logger.info(f"< HTTP/1.1 {response.status} {response.reason}")
    for name, value in response.headers.items():
        logger.info(f"< {name}: {value}")
    logger.info("<")

    # Optionally log response body
    # body = await response.text()
    # if body:
    #     logger.info(body)


trace_config = TraceConfig()
trace_config.on_request_start.append(on_request_start)
trace_config.on_request_end.append(on_request_end)


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
    relative_path = relative_path.replace("\\", "/")

    remote_target = remote_root + relative_path

    assert remote_target[-1] != "/"
    if Path(local_target).is_dir():
        remote_target += "/"

    return remote_target


async def process_change_added(local_target):
    async with ClientSession(trace_configs=[trace_config]) as session:
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
    async with ClientSession(trace_configs=[trace_config]) as session:
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
    async with ClientSession(trace_configs=[trace_config]) as session:
        # Determine the endpoint that should be deleted
        remote_target = endpoint_from_local_path(local_target)

        # Delete
        async with session.delete(remote_target) as response:
            pass  # TODO


try:
    asyncio.run(main())
except KeyboardInterrupt:
    pass
