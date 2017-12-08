import socket
import asyncio
from aiohttp import web, WSMsgType
from dpkt.ip import IP
from dpkt.ip6 import IP6
import ipaddress
import binascii


PKT_CLS = {
        4: IP,
        6: IP6,
}
ADDR_CLS = {
        4: ipaddress.IPv4Address,
        6: ipaddress.IPv6Address,
}
def parseip(dgram):
    ip_version = (dgram[0] & 0b11110000) >> 4
    pkt_cls = PKT_CLS.get(ip_version)
    if not pkt_cls:
        return None
    return pkt_cls(dgram)
def debugip(pkt):
    addr_cls = ADDR_CLS[pkt.v]
    return {
            'v': pkt.v,
            'src': addr_cls(pkt.src),
            'dst': addr_cls(pkt.dst),
            'data': pkt.data,
    }


async def handler(request):
    print('OPN')
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    async for msg in ws:
        if msg.type == WSMsgType.BINARY:
            dgram = msg.data
            pkt = parseip(dgram)
            print('RCV[IPv%d] %03d' % (pkt.v, len(dgram)), debugip(pkt))

    print('CLS')
    return ws


def start_server(loop):
    bind_address = "192.168.99.1"
    bind_port = 8080
    protocol = web.Server(handler)
    return loop.run_until_complete(loop.create_server(protocol, bind_address, bind_port))


loop = asyncio.get_event_loop()
server = None
try:
    server = start_server(loop)
    print("======= Serving on http://192.168.99.1:8080/ ======")
    loop.run_forever()
except KeyboardInterrupt:
    pass
finally:
    if server:
        server.close()
    loop.close()

