from typing import Dict
import logging
import socket
import asyncio
from ipaddress import ip_address, ip_interface, IPv4Interface, IPv6Interface
from aiohttp import web, WSMsgType, WSMessage
import dpkt
from dpkt.ip import IP
from dpkt.ip6 import IP6
from dpkt.icmp import ICMP
from dpkt.udp import UDP
from dpkt.tcp import TCP
import pyroute2

from .counter import Counter


def get_public_address() -> IPv4Interface:
    raise NotImplemented  # TODO get_public_address()


def start_server(loop: asyncio.AbstractEventLoop=None, bind_address: str='0.0.0.0', bind_port: int=3000):
    """
    :param loop: on which event loop to run the server
    :param bind_address: on which address this server should respond to requests
    :param bind_port: on which port this server should respond to requests
    """
    server = Server(loop=loop, bind_address=bind_address, bind_port=bind_port)
    return server.start()


class Server(object):
    def __init__(self, loop: asyncio.AbstractEventLoop=None, bind_address: str='0.0.0.0', bind_port: int=3000):
        self.logger = logging.getLogger('tunproxy.server')
        self.loop = loop or asyncio.get_event_loop()
        self.bind_address = bind_address
        self.bind_port = bind_port

        # this requires privileged access
        self.icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.icmp_sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        self.loop.add_reader(self.icmp_sock, self.icmp_handler)

        # define virtual network used by peers
        self.vnet = ip_interface('192.168.1.2/31')
        self.vnet_dns = ip_address('8.8.8.8')
        self.rnet = get_public_address()

    def start(self):
        server = None
        try:
            protocol = web.Server(self.http_handler)
            server = self.loop.run_until_complete(self.loop.create_server(protocol, self.bind_address, self.bind_port))
            print("======= Serving on http://%s:%s/ ======" % (self.bind_address, self.bind_port))
            self.loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            if server:
                server.close()
            self.loop.close()

    def icmp_handler(self):
        pass

    async def http_handler(self, request: web.Request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        with ServerClient(ws, self, list(self.vnet.network)[-1], None) as client:
            while True:
                ws_msg = await ws.receive()  # type: WSMessage
                ws_msg.json()
                if ws_msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING):
                    break

                elif ws_msg.type == WSMsgType.TEXT:
                    client.handle_downstream_metamsg(ws_msg.json())

                elif ws_msg.type == WSMsgType.BINARY:
                    ip_version = (ws_msg.data[0] >> 4) & 0xF
                    if ip_version == 4:
                        client.handle_downstream_ipv4(IP(ws_msg.data))
                    elif ip_version == 6:
                        client.handle_downstream_ipv6(IP6(ws_msg.data))

        return ws


class ServerClient(object):
    def __init__(self, ws: web.WebSocketResponse, server: Server, vnet_addr: IPv4Interface, vnet6_addr: IPv6Interface|None):
        self.logger = server.logger.getChild('client')  # type: logging.Logger
        self.ws = ws
        self.server = server
        self.vnet_addr = vnet_addr
        self.vnet6_addr = vnet6_addr
        self.ip_identifier = Counter()

        self.udp_sock = None  # type: socket.socket
        self.tcp_socks = {}  # type: Dict[(bytes, int), socket.socket]

    def __enter__(self):
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.server.loop.add_reader(self.udp_sock, self.handle_upstream_udp)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.udp_sock:
            self.server.loop.remove_reader(self.udp_sock)
            self.udp_sock.close()
        for tcp_sock in self.tcp_socks.values():
            self.server.loop.remove_reader(tcp_sock)
            tcp_sock.close()

    def alloc_tcp(self, addr: bytes, port: int) -> socket.socket:
        key = (addr, port)
        sock = self.tcp_socks.get(key)
        if not sock:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            self.server.loop.add_reader(sock, self.handle_upstream_tcp, sock, addr, port)
            self.tcp_socks[key] = sock
        return sock

    def release_tcp(self, addr: bytes, port: int):
        key = (addr, port)
        sock = self.tcp_socks.get(key)
        if not sock:
            return
        self.server.loop.remove_reader(sock)
        sock.close()

    def gen_ip(self, v=4, **kwargs) -> IP | IP6:
        if v == 4:
            return IP(
                ttl=64,
                off=dpkt.ip.IP_DF,
                dst=self.vnet_addr.packed,
                **kwargs,
                id=self.ip_identifier.get_inc(),
            )
        elif v == 6:
            return IP6(
                **kwargs,
                id=self.ip_identifier.get_inc(),
                dst=self.vnet6_addr.packed,
            )
        else:
            raise NotImplemented

    def send_downstream_ip(self, **kwargs):
        pkt = self.gen_ip(**kwargs)
        dgram = bytes(pkt)

        self.logger.debug('SND %03d %r', len(dgram), pkt)

        return self.ws.send_bytes(dgram)

    def send_upstream_ip(self, sock: socket.socket, **kwargs):
        pkt = self.gen_ip(**kwargs)
        dgram = bytes(pkt)

        #self.logger.debug('SND %03d %r', len(dgram), pkt)

        return sock.send(dgram)

    def sendto_upstream_ip(self, sock: socket.socket, **kwargs):
        pkt = self.gen_ip(**kwargs)
        dgram = bytes(pkt)

        #self.logger.debug('SND %03d %r', len(dgram), pkt)

        return sock.sendto(dgram, (str(ip_address(pkt.dst)), pkt.data.dport))

    def handle_downstream_metamsg(self, msg: dict):
        if msg['type'] == 'GET_IP':
            self.ws.send_json({
                'type': 'SET_IP',
                'ip': str(self.vnet_addr.ip),
                'mask': str(self.vnet_addr.network.netmask),
                'gw': str(self.server.vnet.ip),
                'dns': str(self.server.vnet_dns),
            })

    def handle_downstream_ipv4(self, pkt: IP):
        self.logger.debug('RCV %03d %r', len(pkt), pkt)

        if pkt.p == dpkt.ip.IP_PROTO_ICMP:
            return self.handle_downstream_icmp(pkt.dst, pkt.data)

        elif pkt.p == dpkt.ip.IP_PROTO_UDP:
            return self.handle_downstream_udp(pkt.dst, pkt.data)

        elif pkt.p == dpkt.ip.IP_PROTO_TCP:
            return self.handle_downstream_tcp(pkt.dst, pkt.data)

        else:
            pass  # unsupported protocol

    def handle_downstream_ipv6(self, pkt: IP6):
        self.logger.debug('RCV %03d %r', len(pkt), pkt)
        pass  # unsupported protocol

    def handle_downstream_icmp(self, dst: bytes, pkt: ICMP):
        if dst == self.server.vnet.ip.packed and pkt.ty:
            return self.send_downstream_ip(
                src=self.server.vnet.ip.packed,
                p=dpkt.ip.IP_PROTO_ICMP,
                data=ICMP(
                    type=dpkt.icmp.ICMP_ECHOREPLY,
                    data=pkt.data,
                ),
            )
        else:
            return self.send_upstream_ip(self.server.icmp_sock,
                    src=self.server.rnet.ip.packed,
                    dst=dst,
                    data=ICMP(
                        type=dpkt.icmp.ICMP_ECHOREPLY,
                        data=pkt.data,
                    ),
            )

    def handle_downstream_udp(self, dst: bytes, pkt: UDP):
        return self.sendto_upstream_ip(self.udp_sock,
                src=self.server.rnet.ip.packed,
                dst=dst,
                data=pkt,
        )

    def handle_downstream_tcp(self, dst: bytes, pkt: TCP):
        pass

    def handle_upstream_udp(self):
        # TODO find maximum block size to receive so that the forwarded packet fit into MTU
        data, sender = self.udp_sock.recvfrom(500)

    def handle_upstream_tcp(self, sock: socket.socket, addr: bytes, port: int):
        # TODO find maximum block size to receive so that the forwarded packet fit into MTU
        data = sock.recv(500)


class ServerClientTcp(object):
    def __init__(self, client: ServerClient):
        self.client = client
