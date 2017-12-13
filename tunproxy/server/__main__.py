import socket
import asyncio
from aiohttp import web, WSMsgType
import binascii
import json
from ipaddress import ip_address
from ..net import parseip, debugip
import dpkt.tcp
import dpkt.ip
import dpkt.icmp
from dpkt.ip import IP
from dpkt.udp import UDP
from dpkt.icmp import ICMP


BIND_ADDRESS = ip_address('192.168.99.101')
BIND_PORT = 8080
PUBLIC_SERVER_ADDRESS = ip_address('10.0.2.15')
PRIVATE_SERVER_ADDRESS = ip_address('192.168.100.1')
PRIVATE_SERVER_MASK = 24
PRIVATE_CLIENT_ADDRESS = ip_address('192.168.100.100')
DNS_SERVER_ADDRESS = ip_address('192.168.1.254')
ALLOW_IPV = [4]


class Counter(object):
    def __init__(self, initial=1):
        self._value = initial
    def get(self):
        self._value += 1
        return self._value


CLIENTS = []
IP_ID = Counter()


def icmp_upstream_handler(upstream):
    dgram, from_addr = upstream.recvfrom(1500)
    pkt = parseip(dgram)
    print('RCV[%8s] %03d %r' % ('upstream', len(dgram), pkt))

    client_pkt = IP(
        v=4,
        id=IP_ID.get(),
        src=pkt.src,
        dst=PRIVATE_CLIENT_ADDRESS.packed,
        p=dpkt.ip.IP_PROTO_ICMP,
        off=dpkt.ip.IP_DF,
        ttl=pkt.ttl - 1,
        data=ICMP(
            type=dpkt.icmp.ICMP_ECHOREPLY,
            code=0,
            data=pkt.data.data,
        ),
    )
    client_dgram = bytes(client_pkt)
    for ws in CLIENTS:
        ws.send_bytes(client_dgram)


def udp_upstream_handler(upstream, ws, nat):
    data, from_addr = upstream.recvfrom(1500)
    src = ip_address(from_addr[0])
    sport = from_addr[1]
    dport = nat.get((dpkt.ip.IP_PROTO_UDP, src.packed, sport))
    if not dport:
        return

    client_pkt = IP(
        v=4,
        id=IP_ID.get(),
        src=src.packed,
        dst=PRIVATE_CLIENT_ADDRESS.packed,
        p=dpkt.ip.IP_PROTO_UDP,
        off=dpkt.ip.IP_DF,
        ttl=64,
        data=UDP(
            sport=sport,
            dport=dport,
            ulen=8+len(data),
            data=data,
        ),
    )
    print('RCV[%8s] %03d %r' % ('upstream', len(client_pkt), client_pkt))
    ws.send_bytes(bytes(client_pkt))


def tcp_upstream_handler(upstream, ws, nat):
    data = upstream.recv(1500)
    # print('RCV[%8s] %03d %r' % ('upstream', len(dgram), pkt))


async def handler(request):
    print('OPN')
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    CLIENTS.append(ws)
    nat = {}
    
    # UDP
    udp_upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    loop.add_reader(udp_upstream, udp_upstream_handler, udp_upstream, ws, nat)
    # TCP
    tcp_upstreams = {}

    while True:
        msg = await ws.receive()
        if msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED):
            break

        elif msg.type == WSMsgType.TEXT:
            msg = json.loads(msg.data)
            if msg['type'] == 'GET_IP':
                ws.send_json({
                    'type': 'SET_IP',
                    'ip': str(PRIVATE_CLIENT_ADDRESS),
                    'mask': PRIVATE_SERVER_MASK,
                    'gw': str(PRIVATE_SERVER_ADDRESS),
                    'dns': str(DNS_SERVER_ADDRESS),
                })

        elif msg.type == WSMsgType.BINARY:
            dgram = msg.data
            pkt = parseip(dgram)
            print('RCV[%8s] %03d %r' % ('tun', len(dgram), pkt))

            if pkt.v not in ALLOW_IPV:
                continue

            if pkt.p == dpkt.ip.IP_PROTO_ICMP:
                if pkt.dst == PRIVATE_SERVER_ADDRESS.packed:
                    await ws.send_bytes(bytes(IP(
                        v=4,
                        id=IP_ID.get(),
                        src=PRIVATE_SERVER_ADDRESS.packed,
                        dst=PRIVATE_CLIENT_ADDRESS.packed,
                        p=dpkt.ip.IP_PROTO_ICMP,
                        off=dpkt.ip.IP_DF,
                        ttl=64,
                        data=ICMP(
                            type=dpkt.icmp.ICMP_ECHOREPLY,
                            code=0,
                            data=pkt.data.data,
                        ),
                    )))
                else:
                    pkt.src = PUBLIC_SERVER_ADDRESS.packed
                    icmp_upstream.sendto(bytes(pkt), (str(ip_address(pkt.dst)), 0))

            elif pkt.p == dpkt.ip.IP_PROTO_UDP:
                # do send
                nat[(pkt.p, pkt.dst, pkt.data.dport)] = pkt.data.sport
                udp_upstream.sendto(bytes(pkt.data.data), (str(ip_address(pkt.dst)), pkt.data.dport))

            elif pkt.p == dpkt.ip.IP_PROTO_TCP:
                # do send
                if pkt.data.flags & dpkt.tcp.TH_SYN:
                    address = (str(ip_address(pkt.dst)), pkt.data.dport)
                    if address in tcp_upstreams:
                        continue

                    tcp_upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        tcp_upstream.connect(address)
                    except socket.timeout:
                        continue
                    tcp_upstreams[address] = tcp_upstream
                    nat[(dpkt.ip.IP_PROTO_TCP, pkt.dst, pkt.data.dport)] = pkt.data.sport
                    loop.add_reader(tcp_upstream, tcp_upstream_handler, tcp_upstream, ws, nat)
                    
                    pkt.id = IP_ID.get()
                    pkt.dst = PRIVATE_CLIENT_ADDRESS.packed
                    pkt.src = ip_address(address[0]).packed
                    pkt.data.flags |= dpkt.tcp.TH_ACK
                    ws.send_bytes(bytes(pkt))

                elif pkt.data.flags & dpkt.tcp.TH_FIN:
                    address = (str(ip_address(pkt.dst)), pkt.data.dport)
                    tcp_upstream = tcp_upstreams.get(address)
                    if not tcp_upstream:
                        continue
                    try:
                        loop.remove_reader(tcp_upstream)
                        tcp_upstream.close()
                        del tcp_upstreams[address]
                        
                        pkt.dst = PRIVATE_CLIENT_ADDRESS.packed
                        pkt.src = ip_address(address[0]).packed
                        pkt.flags |= dpkt.tcp.TH_ACK
                        ws.send_bytes(bytes(pkt))
                    except:
                        pass
                else:
                    address = (str(ip_address(pkt.dst)), pkt.data.dport)
                    tcp_upstream = tcp_upstreams.get(address)
                    if not tcp_upstream:
                        continue
                    tcp_upstream.send(pkt.data.data)

            else:
                print('do nothing for protocol', pktproto)
                # do nothing
                continue


    print('CLS')
    CLIENTS.remove(ws)
    loop.remove_reader(udp_upstream)
    udp_upstream.close()
    return ws


def start_server(loop):
    protocol = web.Server(handler)
    return loop.run_until_complete(loop.create_server(protocol, str(BIND_ADDRESS), BIND_PORT))


loop = asyncio.get_event_loop()

# UDP
# ICMP
icmp_upstream = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
icmp_upstream.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
loop.add_reader(icmp_upstream, icmp_upstream_handler, icmp_upstream)

server = None
try:
    server = start_server(loop)
    print("======= Serving on http://%s:%s/ ======" % (BIND_ADDRESS, BIND_PORT))
    loop.run_forever()
except KeyboardInterrupt:
    pass
finally:
    if server:
        server.close()
    loop.close()

