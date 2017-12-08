import asyncio
from aiohttp import web


async def handler(request):
    ws = web.WebSocketResponse()
    print('START')
    await ws.prepare(request)
    print('RUN')

    async for msg in ws:
        print('MSG', msg)

    print('CLOSE')

    return ws


async def main(loop):
    server = web.Server(handler)
    await loop.create_server(server, "127.0.0.1", 8080)
    print("======= Serving on http://127.0.0.1:8080/ ======")

    # pause here for very long time by serving HTTP requests and
    # waiting for keyboard interruption
    await asyncio.sleep(100*3600)


loop = asyncio.get_event_loop()
try:
    loop.run_until_complete(main(loop))
except KeyboardInterrupt:
    pass
finally:
    loop.close()
