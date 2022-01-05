import os
import struct
import socket

cur_dir = os.path.dirname(os.path.abspath(__file__))


def project_file(name):
    return os.path.join(cur_dir, name)


def b2str(b):
    return 'true' if b else 'false'


class NetUtils:

    PROTO_L3 = {
        'LOOP': 0x0060,
        'PUP': 0x0200,
        'PUPAT': 0x0201,
        'TSN': 0x22F0,
        'ERSPAN2': 0x22EB,
        'IP': 0x0800,
        'X25': 0x0805,
        'ARP': 0x0806,
        'BPQ': 0x08FF,
        'IEEEPUP': 0x0a00,
        'IEEEPUPAT': 0x0a01,
        'BATMAN': 0x4305,
        'DEC': 0x6000,
        'DNA_DL': 0x6001,
        'DNA_RC': 0x6002,
        'DNA_RT': 0x6003,
        'LAT': 0x6004,
        'DIAG': 0x6005,
        'CUST': 0x6006,
        'SCA': 0x6007,
        'TEB': 0x6558,
        'RARP': 0x8035,
        'ATALK': 0x809B,
        'AARP': 0x80F3,
        '8021Q': 0x8100,
        'ERSPAN': 0x88BE,
        'IPX': 0x8137,
        'IPV6': 0x86DD,
        'PAUSE': 0x8808,
        'SLOW': 0x8809,
        'WCCP': 0x883E,
        'MPLS_UC': 0x8847,
        'MPLS_MC': 0x8848,
        'ATMMPOA': 0x884c,
        'PPP_DISC': 0x8863,
        'PPP_SES': 0x8864,
        'LINK_CTL': 0x886c,
        'ATMFATE': 0x8884,
        'PAE': 0x888E,
        'AOE': 0x88A2,
        '8021AD': 0x88A8,
        '802_EX1': 0x88B5,
        'PREAUTH': 0x88C7,
        'TIPC': 0x88CA,
        'LLDP': 0x88CC,
        'MACSEC': 0x88E5,
        '8021AH': 0x88E7,
        'MVRP': 0x88F5,
        '1588': 0x88F7,
        'NCSI': 0x88F8,
        'PRP': 0x88FB,
        'FCOE': 0x8906,
        'IBOE': 0x8915,
        'TDLS': 0x890D,
        'FIP': 0x8914,
        '80221': 0x8917,
        'HSR': 0x892F,
        'NSH': 0x894F,
        'LOOPBACK': 0x9000,
        'QINQ1': 0x9100,
        'QINQ2': 0x9200,
        'QINQ3': 0x9300,
        'EDSA': 0xDADA,
        'DSA_8021Q': 0xDADB,
        'IFE': 0xED3E,
        'AF_IUCV': 0xFBFB,
        '802_3_MIN': 0x0600,
        '802_3': 0x0001,
        'AX25': 0x0002,
        'ALL': 0x0003,
        '802_2': 0x0004,
        'SNAP': 0x0005,
        'DDCMP': 0x0006,
        'WAN_PPP': 0x0007,
        'PPP_MP': 0x0008,
        'LOCALTALK': 0x0009,
        'CAN': 0x000C,
        'CANFD': 0x000D,
        'PPPTALK': 0x0010,
        'TR_802_2': 0x0011,
        'MOBITEX': 0x0015,
        'CONTROL': 0x0016,
        'IRDA': 0x0017,
        'ECONET': 0x0018,
        'HDLC': 0x0019,
        'ARCNET': 0x001A,
        'DSA': 0x001B,
        'TRAILER': 0x001C,
        'PHONET': 0x00F5,
        'IEEE802154': 0x00F6,
        'CAIF': 0x00F7,
        'XDSA': 0x00F8,
        'MAP': 0x00F9,
    }

    PROTO_L4 = {
        'ICMP': 1,
        'IGMP': 2,
        'IPIP': 4,
        'TCP': 6,
        'EGP': 8,
        'PUP': 12,
        'UDP': 17,
        'IDP': 22,
        'TP': 29,
        'DCCP': 33,
        'IPV6': 41,
        'RSVP': 46,
        'GRE': 47,
        'ESP': 50,
        'AH': 51,
        'MTP': 92,
        'BEETPH': 94,
        'ENCAP': 98,
        'PIM': 103,
        'COMP': 108,
        'SCTP': 132,
        'UDPLITE': 136,
        'MPLS': 137,
        'RAW': 255,
    }

    ICMP_TYPE = {
        'ICMP_ECHOREPLY': 0,
        'ICMP_DEST_UNREACH': 3,
        'ICMP_SOURCE_QUENCH': 4,
        'ICMP_REDIRECT': 5,
        'ICMP_ECHO': 8,
        'ICMP_TIME_EXCEEDED': 11,
        'ICMP_PARAMETERPROB': 12,
        'ICMP_TIMESTAMP': 13,
        'ICMP_TIMESTAMPREPLY': 14,
        'ICMP_INFO_REQUEST': 15,
        'ICMP_INFO_REPLY': 16,
        'ICMP_ADDRESS': 17,
        'ICMP_ADDRESSREPLY': 18,
    }

    @staticmethod
    def ip2int(addr):
        return struct.unpack("!I", socket.inet_aton(addr))[0]

    @staticmethod
    def int2ip(addr):
        return socket.inet_ntoa(struct.pack("!I", addr))

    @staticmethod
    def proto2int(proto):
        proto = proto.upper()
        if proto in NetUtils.PROTO_L3:
            return NetUtils.PROTO_L3[proto], 3
        if proto in NetUtils.PROTO_L4:
            return NetUtils.PROTO_L4[proto], 4
        return (None, None)

    @staticmethod
    def int2proto(proto, level):
        if level == 3:
            for (k, v) in NetUtils.PROTO_L3.items():
                if v == proto:
                    return k
        elif level == 4:
            for (k, v) in NetUtils.PROTO_L4.items():
                if v == proto:
                    return k
        return None

    @staticmethod
    def int2tcp_flags(flags):
        res = []
        if flags & (1 << 4):
            res.append('A')
        if flags & (1 << 3):
            res.append('P')
        if flags & (1 << 1):
            res.append('S')
        if flags & 1:
            res.append('F')
        if flags & (1 << 2):
            res.append('R')
        return ','.join(res)

    @staticmethod
    def tcp_flags2int(flags):
        res = 0
        if 'A' in flags:
            res += (1 << 4)
        if 'P' in flags:
            res += (1 << 3)
        if 'F' in flags:
            res += (1 << 0)
        if 'S' in flags:
            res += (1 << 1)
        if 'R' in flags:
            res += (1 << 2)
        return res
