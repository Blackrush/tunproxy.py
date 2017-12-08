from pytap2 import TapDevice
from dpkt.ip import IP
from dpkt.ip6 import IP6
from socket import create_connection
from select import select
import json
from urllib.parse import urlparse
import binascii
import websocket


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


def start_server():
    with open('tunproxy.json', 'r') as config_file:
        config = json.load(config_file)

    with WebSocketWrapper(websocket.create_connection(config['upstream_url'])) as upstream:
        with TapDevice() as tun:
            # tun.ifconfig(address=config['tunnel_network'])
            reverse_table = {
                    tun: ('tun', upstream),
                    upstream: ('upstream', tun),
            }

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

                        print('RCV[%8s] %03d' % (rid, len(dgram)), binascii.b2a_hex(dgram))
                        # ip_version = (dgram[0] & 0b11110000) >> 4
                        # pkt = IP6(dgram) if ip_version == 6 else IP(dgram)
                        # print('RCV[%s]' % rid, pkt.__dict__)
                        rev.write(dgram)
                except KeyboardInterrupt:
                    break

if __name__ == '__main__':
    start_server()

# $ curl -v http://google.com/
# *   Trying 192.168.34.62...
# * TCP_NODELAY set
# * Connected to 192.168.34.62 (192.168.34.62) port 3128 (#0)
# * Proxy auth using Basic with user '[REDACTED]'
# > GET http://google.com/ HTTP/1.1
# > Host: google.com
# > Proxy-Authorization: Basic [REDACTED]
# > User-Agent: curl/7.55.1
# > Accept: */*
# > Proxy-Connection: Keep-Alive
# > 
# < HTTP/1.1 302 Moved Temporarily
# < Cache-Control: private
# < Content-Type: text/html; charset=UTF-8
# < Referrer-Policy: no-referrer
# < Location: http://www.google.fr/?gfe_rd=cr&dcr=0&ei=iwooWpSlAe3t8wea1bKoCw
# < Content-Length: 268
# < Date: Wed, 06 Dec 2017 15:19:39 GMT
# < X-Cache: MISS from inf-srv-enclos
# < Via: 1.1 inf-srv-enclos (squid/3.2.5-20121213-r11739)
# < Connection: keep-alive
# < 
# <HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
# <TITLE>302 Moved</TITLE></HEAD><BODY>
# <H1>302 Moved</H1>
# The document has moved
# <A HREF="http://www.google.fr/?gfe_rd=cr&amp;dcr=0&amp;ei=iwooWpSlAe3t8wea1bKoCw">here</A>.
# </BODY></HTML>
# * Connection #0 to host 192.168.34.62 left intact

