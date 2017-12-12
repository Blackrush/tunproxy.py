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


BIND_ADDRESS = ip_address('192.168.99.101')
BIND_PORT = 8080
PUBLIC_SERVER_ADDRESS = ip_address('10.0.2.15')
PRIVATE_SERVER_ADDRESS = ip_address('192.168.100.1')
PRIVATE_SERVER_MASK = 24
PRIVATE_CLIENT_ADDRESS = ip_address('192.168.100.100')
DNS_SERVER_ADDRESS = ip_address('192.168.1.254')
ALLOW_IPV = [4]


def udp_upstream_handler(upstream, ws, nat):
    data, from_addr = upstream.recvfrom(1500)
    dport = nat[('UDP', ip_address(from_addr[0]).packed, from_addr[1])]
    pkt = IP(
        id=1,
        src=ip_address(from_addr[0]).packed,
        dst=PRIVATE_CLIENT_ADDRESS.packed,
        p=dpkt.ip.IP_PROTO_UDP,
        data=UDP(
            sport=from_addr[1],
            dport=dport,
            ulen=8+len(data),
            data=data,
        ),
    )
    dgram = bytes(pkt)
    print('RCV[%8s] %03d %r' % ('upstream', len(dgram), pkt))
    ws.send_bytes(dgram)


def icmp_upstream_handler(upstream, ws, nat):
    dgram, from_addr = upstream.recvfrom(1500)
    pkt = parseip(dgram)
    print('RCV[%8s] %03d %r' % ('upstream', len(dgram), pkt))


def tcp_upstream_handler(upstream, ws, nat):
    data = upstream.recv(1500)
    print('RCV[%8s] %03d %r' % ('upstream', len(dgram), pkt))


async def handler(request):
    print('OPN')
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    
    nat = {}
    udp_upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    loop.add_reader(udp_upstream, udp_upstream_handler, udp_upstream, ws, nat)
    icmp_upstream = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_upstream.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
    loop.add_reader(icmp_upstream, icmp_upstream_handler, icmp_upstream, ws, nat)
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
                })

        elif msg.type == WSMsgType.BINARY:
            dgram = msg.data
            pkt = parseip(dgram)
            print('RCV[%8s] %03d %r' % ('tun', len(dgram), pkt))

            if pkt.v not in ALLOW_IPV:
                continue

            pktproto = type(pkt.data).__name__

            if pkt.p == dpkt.ip.IP_PROTO_ICMP:
                if pkt.dst == PRIVATE_SERVER_ADDRESS.packed:
                    pkt.src, pkt.dst = pkt.dst, pkt.src
                    ws.send_bytes(bytes(pkt))
                else:
                    icmp_upstream.sendto(bytes(pkt.data), (str(ip_address(pkt.dst)), 0))

            elif pkt.p == dpkt.ip.IP_PROTO_UDP:
                pkt.src = PUBLIC_SERVER_ADDRESS.packed
                if pkt.data.dport == 53:
                    pkt.dst = DNS_SERVER_ADDRESS.packed

                # do send
                nat[(pktproto, pkt.dst, pkt.data.dport)] = pkt.data.sport
                udp_upstream.sendto(bytes(pkt.data.data), (str(ip_address(pkt.dst)), pkt.data.dport))

            elif pkt.p == pkt.ip.IP_PROTO_TCP:
                pkt.src = PUBLIC_SERVER_ADDRESS.packed

                # do send
                if pkt.data.flags & dpkt.tcp.TH_SYN:
                    address = (str(ip_address(pkt.dst)), pkt.data.dport)
                    if address in tcp_upstreams:
                        continue
                    try:
                        tcp_upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        tcp_upstream.connect(address)
                        tcp_upstreams[address] = tcp_upstream
                        nat[(pktproto, pkt.dst, pkt.data.dport)] = pkt.data.sport
                        loop.add_reader(tcp_upstream, tcp_upstream_handler, tcp_upstream, ws, nat)
                        
                        pkt.dst = PRIVATE_CLIENT_ADDRESS.packed
                        pkt.src = ip_address(address[0]).packed
                        pkt.flags |= dpkt.tcp.TH_ACK
                        ws.send_bytes(bytes(pkt))
                    except:
                        pass
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
    loop.remove_reader(udp_upstream)
    udp_upstream.close()
    for address, tcp_upstream in tcp_upstreams.items():
        loop.remove_reader(tcp_upstream)
        tcp_upstream.close()
    return ws


def start_server(loop):
    protocol = web.Server(handler)
    return loop.run_until_complete(loop.create_server(protocol, str(BIND_ADDRESS), BIND_PORT))


loop = asyncio.get_event_loop()
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

