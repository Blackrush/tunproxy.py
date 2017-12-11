from pytap2 import TapDevice, TapMode
from dpkt.ethernet import Ethernet
from socket import create_connection
from select import select
import json
from urllib.parse import urlparse
import binascii
import json
import websocket
from .net import parseip, debugip


def prettymac(mac):
    hexmac = binascii.hexlify(mac).decode('ascii')
    return ':'.join(hexmac[i:i+2] for i in range(0, len(hexmac), 2))


def getconnected(self):
    return True
TapDevice.connected = property(getconnected)


class WebSocketWrapper(object):
    def __init__(self, ws):
        self.ws = ws

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.ws.connected:
            self.ws.close()

    @property
    def connected(self):
        return self.ws.connected

    def fileno(self):
        return self.ws.fileno()

    def read(self):
        return self.ws.recv()

    def write(self, data):
        return self.ws.send_binary(data)

    def send_json(self, data):
        return self.ws.send(json.dumps(data))
    def recv_json(self):
        return json.loads(self.read())


def start_server():
    with open('tunproxy.json', 'r') as config_file:
        config = json.load(config_file)

    with WebSocketWrapper(websocket.create_connection(config['upstream_url'])) as upstream:
        with TapDevice() as tun:
            import pyroute2
            ipr = pyroute2.IPRoute()
            iface = ipr.link_lookup(ifname=tun.name)[0]
            reverse_table = {
                    tun: ('tun', upstream),
                    upstream: ('upstream', tun),
            }

            upstream.send_json({'type': 'GET_IP'})
            while True:
                msg = upstream.recv_json()
                if msg['type'] == 'SET_IP':
                    ipr.addr('add', index=iface, address=msg['ip'], mask=msg['mask'])
                    ipr.route('add', dst='default', gateway=msg['gw'])
                    break

            input('Press [Enter] to Start')
            print('Ready!')

            while True:
                try:
                    rlist, wlist, xlist = select([upstream, tun], [], [])
                    for r in rlist:
                        if not r.connected:
                            print('CLS[%8s]' % rid)
                            raise KeyboardInterrupt
                        rid, rev = reverse_table[r]
                        dgram = r.read()
                        if not dgram:
                            print('CLS[%8s]' % rid)
                            raise KeyboardInterrupt

                        # pkt = Ethernet(dgram)
                        # print('RCV', {
                            # 'src': prettymac(pkt.src),
                            # 'dst': prettymac(pkt.dst),
                            # 'type': pkt.type,
                            # 'data': pkt.data,
                        # })
                        pkt = parseip(dgram)
                        # print('RCV[%8s] %03d' % (rid, len(dgram)), binascii.b2a_hex(dgram))
                        print('RCV[%8s] %03d' % (rid, len(dgram)), debugip(pkt))
                        rev.write(dgram)
                except KeyboardInterrupt:
                    break

            ipr.route('del', dst='default')

