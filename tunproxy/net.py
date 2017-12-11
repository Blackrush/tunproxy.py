
import ipaddress
from dpkt.ip import IP
from dpkt.ip6 import IP6

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

