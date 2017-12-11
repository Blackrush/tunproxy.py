import socket
import asyncio
from aiohttp import web, WSMsgType
import binascii
import json
from ipaddress import ip_address
from ..net import parseip, debugip
import dpkt.tcp


BIND_ADDRESS = ip_address('192.168.99.101')
BIND_PORT = 8080
PUBLIC_SERVER_ADDRESS = ip_address('10.0.2.15')
PRIVATE_SERVER_ADDRESS = ip_address('192.168.100.1')
PRIVATE_SERVER_MASK = 24
PRIVATE_CLIENT_ADDRESS = ip_address('192.168.100.100')
DNS_SERVER_ADDRESS = ip_address('192.168.1.254')
ALLOW_IPV = [4]


CLIENTS = {}


async def udp_upstream_handler(upstream, ws):
    data, from_addr = upstream.recvfrom(1500)
    print('RCV[upstream] %03d' % (len(data)), data)


async def tcp_upstream_handler(upstream, ws):
    data = upstream.recv(1500)
    print('RCV[upstream] %03d' % len(data), data)


async def handler(request):
    print('OPN')
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    
    udp_upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    loop.add_reader(udp_upstream, udp_upstream_handler, ws)
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
            print('RCV[     tun] %03d' % len(dgram), debugip(pkt))
            if pkt.v not in ALLOW_IPV:
                continue
            if pkt.dst == PRIVATE_SERVER_ADDRESS.packed:
                continue

            pktproto = type(pkt.data).__name__
            if pktproto == 'UDP':
                pkt.src = PUBLIC_SERVER_ADDRESS.packed
                if pkt.data.dport == 53:
                    pkt.dst = DNS_SERVER_ADDRESS.packed
                CLIENTS[pkt.data.sport] = ws
                print('SND', debugip(pkt))

                # do send
                udp_upstream.sendto(bytes(pkt.data.data), (pkt.dst, pkt.data.dport))
            elif pktproto == 'TCP':
                pkt.src = PUBLIC_SERVER_ADDRESS.packed
                CLIENTS[pkt.data.sport] = ws
                print('SND', debugip(pkt))

                # do send
                if pkt.data.flags & dpkt.tcp.TH_SYN:
                    address = (str(ip_address(pkt.dst)), pkt.data.dport)
                    if address in tcp_upstreams:
                        continue
                    try:
                        print('OPENING TCP CONNECTION TO', address)
                        tcp_upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        tcp_upstream.connect(address)
                        print('TCP CONNECTION OPENED')
                        tcp_upstreams[address] = tcp_upstream
                        loop.add_reader(tcp_upstream, tcp_upstream_handler, ws)
                        
                        pkt.dst = PRIVATE_CLIENT_ADDRESS.packed
                        pkt.src = ip_address(address[0]).packed
                        pkt.flags |= dpkt.tcp.TH_ACK
                        ws.send_binary(bytes(pkt))
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
                        ws.send_binary(bytes(pkt))
                    except:
                        pass
                else:
                    address = (str(ip_address(pkt.dst)), pkt.data.dport)
                    tcp_upstream = tcp_upstreams.get(address)
                    if not tcp_upstream:
                        continue
                    tcp_upstream.send(pkt.data.data)
            else:
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

