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
from dpkt.tcp import TCP


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


class TcpConnection(object):
    CONTROL_METHODS = {
            dpkt.tcp.TH_SYN: 'syn',
            dpkt.tcp.TH_PUSH: 'push',
            dpkt.tcp.TH_FIN: 'fin',
    }

    def __init__(self, loop, ws, addr, port):
        self.loop = loop
        self.ws = ws
        self.seq = 0
        self.seq_ack = 0
        self.client_port = 0
        self.client_seq = 0
        self.addr = addr
        self.port = port
        self.sock = None

    def gen_seq(self, inc=1):
        seq = self.seq
        self.seq += inc
        return seq

    def setup(self, sock):
        self.sock = sock
        self.loop.add_reader(sock, self.recv_upstream)

    def cleanup(self):
        if not self.sock:
            return
        self.loop.remove_reader(self.sock)
        self.sock.close()
        self.sock = None

    def send_ip(self, **kwargs):
        pkt = IP(
            v=4,
            id=IP_ID.get(),
            src=self.addr.packed,
            dst=PRIVATE_CLIENT_ADDRESS.packed,
            p=dpkt.ip.IP_PROTO_TCP,
            off=dpkt.ip.IP_DF,
            ttl=64,
            data=TCP(
                sport=self.port,
                dport=self.client_port,
                **kwargs,
            ),
        )
        dgram = bytes(pkt)
        print('RCV[%8s] %03d %r' % ('upstream', len(dgram), pkt))
        self.ws.send_bytes(dgram)

    def handle(self, pkt):
        if pkt.p != dpkt.ip.IP_PROTO_TCP:
            return

        self.client_seq = pkt.data.seq
        for i in range(0, 8):
            flag = 1 << i
            control_method = TcpConnection.CONTROL_METHODS.get(flag)
            if isinstance(control_method, str):
                control_method = getattr(TcpConnection, control_method, None)
            if control_method and pkt.data.flags & flag:
                return control_method(self, pkt)

    def syn(self, pkt):
        if self.sock:
            # do not overwrite existing connection
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((str(self.addr), self.port))
        except socket.timeout:
            # do nothing and let the websocket retry
            return
        
        self.setup(sock)
        self.client_port = pkt.data.sport

        self.send_ip(
            seq=self.gen_seq(),
            ack=self.client_seq + 1,
            flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK,
            # TODO MSS
        )

    def push(self, pkt):
        if not self.sock:
            # do nothing
            return

        self.sock.send(pkt.data.data)

        self.client_seq += pkt.len - 40
        self.send_ip(
            flags=dpkt.tcp.TH_ACK,
            seq=self.seq,
            ack=self.client_seq,
        )

    def fin(self, pkt=None):
        if not self.sock:
            # trying to close something already closed
            return

        self.cleanup()

        self.send_ip(
            flags=dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK,
            seq=self.gen_seq(),
            ack=self.client_seq + 1,
        )

    def recv_upstream(self):
        data = self.sock.recv(1460)
        if not data:
            return self.fin()

        self.push_now(data)

    def push_now(self, data):
        self.send_ip(
            flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK,
            seq=self.gen_seq(len(data)),
            ack=self.client_seq,
            data=data,
        )

    def ack(self, pkt):
        pass # TODO re-send missed packets


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
    tcp_connections = {}

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
                address = (pkt.dst, pkt.data.dport)
                tcp_connection = tcp_connections.get(address)
                if not tcp_connection:
                    tcp_connection = TcpConnection(loop, ws, ip_address(pkt.dst), pkt.data.dport)
                    tcp_connections[address] = tcp_connection
                tcp_connection.handle(pkt)

            else:
                print('do nothing for protocol', pktproto)
                # do nothing
                continue


    print('CLS')
    CLIENTS.remove(ws)
    loop.remove_reader(udp_upstream)
    udp_upstream.close()
    for tcp_connection in tcp_connections.values():
        tcp_connection.cleanup()
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

