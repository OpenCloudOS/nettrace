#!/usr/bin/python3
import argparse
import json
import struct
import socket
import bcc
import ctypes
import re
import os

from config import project_file


class NetUtils:

    PROTO_L3 = {
        'LOOP':	0x0060,
        'PUP':	0x0200,
        'PUPAT':	0x0201,
        'TSN':	0x22F0,
        'ERSPAN2':	0x22EB,
        'IP':	0x0800,
        'X25':	0x0805,
        'ARP':	0x0806,
        'BPQ':	0x08FF,
        'IEEEPUP':	0x0a00,
        'IEEEPUPAT':	0x0a01,
        'BATMAN':	0x4305,
        'DEC':       0x6000,
        'DNA_DL':    0x6001,
        'DNA_RC':    0x6002,
        'DNA_RT':    0x6003,
        'LAT':       0x6004,
        'DIAG':      0x6005,
        'CUST':      0x6006,
        'SCA':       0x6007,
        'TEB':	0x6558,
        'RARP':      0x8035,
        'ATALK':	0x809B,
        'AARP':	0x80F3,
        '8021Q':	0x8100,
        'ERSPAN':	0x88BE,
        'IPX':	0x8137,
        'IPV6':	0x86DD,
        'PAUSE':	0x8808,
        'SLOW':	0x8809,
        'WCCP':	0x883E,
        'MPLS_UC':	0x8847,
        'MPLS_MC':	0x8848,
        'ATMMPOA':	0x884c,
        'PPP_DISC':	0x8863,
        'PPP_SES':	0x8864,
        'LINK_CTL':	0x886c,
        'ATMFATE':	0x8884,
        'PAE':	0x888E,
        'AOE':	0x88A2,
        '8021AD':	0x88A8,
        '802_EX1':	0x88B5,
        'PREAUTH':	0x88C7,
        'TIPC':	0x88CA,
        'LLDP':	0x88CC,
        'MACSEC':	0x88E5,
        '8021AH':	0x88E7,
        'MVRP':	0x88F5,
        '1588':	0x88F7,
        'NCSI':	0x88F8,
        'PRP':	0x88FB,
        'FCOE':	0x8906,
        'IBOE':	0x8915,
        'TDLS':	0x890D,
        'FIP':	0x8914,
        '80221':	0x8917,
        'HSR':	0x892F,
        'NSH':	0x894F,
        'LOOPBACK':	0x9000,
        'QINQ1':	0x9100,
        'QINQ2':	0x9200,
        'QINQ3':	0x9300,
        'EDSA':	0xDADA,
        'DSA_8021Q':	0xDADB,
        'IFE':	0xED3E,
        'AF_IUCV':   0xFBFB,
        '802_3_MIN':	0x0600,
        '802_3':	0x0001,
        'AX25':	0x0002,
        'ALL':	0x0003,
        '802_2':	0x0004,
        'SNAP':	0x0005,
        'DDCMP':     0x0006,
        'WAN_PPP':   0x0007,
        'PPP_MP':    0x0008,
        'LOCALTALK': 0x0009,
        'CAN':	0x000C,
        'CANFD':	0x000D,
        'PPPTALK':	0x0010,
        'TR_802_2':	0x0011,
        'MOBITEX':	0x0015,
        'CONTROL':	0x0016,
        'IRDA':	0x0017,
        'ECONET':	0x0018,
        'HDLC':	0x0019,
        'ARCNET':	0x001A,
        'DSA':	0x001B,
        'TRAILER':	0x001C,
        'PHONET':	0x00F5,
        'IEEE802154': 0x00F6,
        'CAIF':	0x00F7,
        'XDSA':	0x00F8,
        'MAP':	0x00F9,
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

    @staticmethod
    def b2str(b):
        return 'true' if b else 'false'


class TracePoint:
    KPROBE_PREFIX = 'nettrace_kprobe__'
    KRETPROBE_PREFIX = 'nettrace_kretprobe__'
    TP_PREFIX = 'nettrace_tp__'
    TYPE_TRACEPOINT = 'tracepoint'
    TYPE_KPROBE = 'kprobe'
    TYPE_KRETPROBE = 'kretprobe'

    _functions = []
    _tracers = []
    _all_tracer = None

    _v_tracer = {
        '4.14': [
            {'name': '__netif_receive_skb_core', 'skb': 0, 'level': 1},
        ],
        '5.4': [
            {'name': '__netif_receive_skb_core', 'pskb': 0, 'level': 1},
        ]
    }

    @staticmethod
    def get_all_tracer():
        if TracePoint._all_tracer:
            return TracePoint._all_tracer
        with open(project_file('tracer.json'), 'r') as f:
            data = f.read()
            tracer = json.loads(data)
            TracePoint._all_tracer = tracer
            f.close()
            return tracer

    @staticmethod
    def is_item(tracer):
        return 'children' not in tracer

    @staticmethod
    def is_tp(item):
        return item.get('type') == TracePoint.TYPE_TRACEPOINT

    @staticmethod
    def is_ret_enabled(item):
        return item.get('ret_enabled')

    @staticmethod
    def is_valid(item):
        if TracePoint.is_tp(item):
            return True
        if 'skb' not in item and 'pskb' not in item:
            return False
        return True

    @staticmethod
    def is_ret_only(item):
        return item.get('ret_only')

    @staticmethod
    def has_any_ret():
        for item in TracePoint._functions:
            if TracePoint.is_ret_enabled(item):
                return True
        return False

    @staticmethod
    def is_end(item):
        return item.get('is_end')

    @staticmethod
    def is_clone(item):
        return item['name'] == 'skb_clone'

    @staticmethod
    def get_tracer(tracer, root=None):
        if not root:
            root = TracePoint.get_all_tracer()
            if tracer == root['name']:
                return root
        for item in root['children']:
            if item['name'] == tracer:
                return item
            elif not TracePoint.is_item(item):
                t = TracePoint.get_tracer(tracer, item)
                if t:
                    return t
        return None

    @staticmethod
    def get_items(tracer):
        result = []
        if not tracer:
            return []
        if TracePoint.is_item(tracer):
            result.append(tracer)
        else:
            for v in tracer['children']:
                if TracePoint.is_item(v):
                    result.append(v)
                else:
                    result += TracePoint.get_items(v)
        return result

    @staticmethod
    def bind_parent(root):
        for i in root['children']:
            i['parent'] = root
            if TracePoint.is_item(i):
                continue
            TracePoint.bind_parent(i)

    @staticmethod
    def get_parent_str(tp):
        p = tp['parent']
        res = ''
        while p and 'visual' in p:
            res += '-> %s' % p['name']
        return res

    @staticmethod
    def print_tracer(tracer, tab=''):
        if TracePoint.is_item(tracer):
            if tracer.get('hidden'):
                return
            if 'attached' in tracer:
                status = 'success' if tracer['attached'] else 'failed'
                print('%s%s[%s]' % (tab, tracer['name'], status))
            else:
                print('%s%s' % (tab, tracer['name']))
            return
        else:
            print('%s%s: %s' % (tab, tracer['name'], tracer['desc']))

        for i in tracer['children']:
            TracePoint.print_tracer(i, tab + '    ')

    @staticmethod
    def fix_version():
        import subprocess
        code, ver_str = subprocess.getstatusoutput('uname -r')
        if code != 0:
            return
        m = re.match(r'([0-9]+\.[0-9]+)\.', ver_str)
        if not m:
            return
        ver = m.group(1)
        if ver not in TracePoint._v_tracer:
            Helper.pr_warn('''kernel version not found! You can add your kernel
version in '_v_tracer' of nettrace.py\n''')
            return
        for item in TracePoint._v_tracer[ver]:
            origin = TracePoint.get_tracer(item['name'])
            origin.update(item)

    @staticmethod
    def init_functions():
        functions, tracers, stack_funcs = [], [], []
        for tracer_str in set(Helper.get_tracer()):
            tracer = TracePoint.get_tracer(tracer_str)
            if not tracer:
                Helper.pr_warn('the tracer:%s not found' % tracer_str)
                continue
            functions += TracePoint.get_items(tracer)
            tracers.append(tracer)

        for t in set(Helper.get_stack_tracer()):
            stack_funcs += TracePoint.get_items(TracePoint.get_tracer(t))

        enable_func = [i for i in functions if i.get('is_end')]
        if not enable_func and Helper.tl_enabled():
            tracer = TracePoint.get_tracer('life')
            functions += TracePoint.get_items(tracer)
            tracers.append(tracer)
            Helper.pr_warn('''no end tracer is found in timeline mode!
"life" tracer is enabled automatically
''')

        for f in functions:
            if stack_funcs:
                if f in stack_funcs:
                    f['stack'] = True
                else:
                    f['stack'] = False
            elif Helper.get_args().stack:
                f['stack'] = True
            else:
                f['stack'] = False

        TracePoint._functions = functions
        TracePoint._tracers = tracers
        TracePoint.bind_parent(TracePoint.get_all_tracer())
        TracePoint.fix_version()

        for item in functions:
            p = item['parent']
            parents = []
            while p and 'visual' in p:
                parents.append(p['name'])
                p = p.get('parent')
            item['parent_str'] = '->'.join(parents)
            if Helper.get_args().ret:
                item['ret_enabled'] = True
            if Helper.tl_enabled() and TracePoint.is_clone(item):
                item['ret_only'] = True
                item['ret_enabled'] = True

    @staticmethod
    def generate_func_code():
        kprobe_template = '''int %s%s(struct pt_regs *regs, %s)
        { BPF_prep DO_TRACE(regs, %d%s) }\n'''
        kretprobe_template = '''int %s%s(void *ctx)
        { return ret_trace(ctx, %d, %s); }\n'''
        tp_template = '''TRACEPOINT_PROBE(%s)
        { BPF_prep DO_TRACE(args, %d%s) }\n'''
        ph_functions = ''

        for func_index in range(len(TracePoint._functions)):
            func = TracePoint._functions[func_index]
            trace_params = []

            if not TracePoint.is_valid(func):
                continue

            if Helper.ret_enabled():
                trace_params.append(NetUtils.b2str(
                    TracePoint.is_ret_enabled(func)))
                trace_params.append(NetUtils.b2str(
                    TracePoint.is_ret_only(func)))
            if Helper.stack_enabled():
                is_stack = NetUtils.b2str(func['stack'])
                trace_params.append(is_stack)
            if Helper.skb_mode_enabled():
                trace_params.append(NetUtils.b2str(TracePoint.is_end(func)))
            trace_params = ', '.join(trace_params)
            if trace_params:
                trace_params = ', ' + trace_params

            if TracePoint.is_tp(func):
                tp_info = func['tp'].split(':')
                if not bcc.BPF.tracepoint_exists(tp_info[0], tp_info[1]):
                    continue
                tp_name = func['tp'].replace(':', ', ')
                ph_functions += tp_template % (tp_name, func_index,
                                               trace_params)
                bpf_prep = 'struct sk_buff *skb = args->%s;' % func['skb']
            else:
                name = func['name']
                if 'regex' not in func and bcc.BPF.ksymname(name) < 0:
                    continue
                if 'skb' in func:
                    pad_index = func['skb']
                    skb_param = 'struct sk_buff *skb'
                    bpf_prep = ''
                elif 'pskb' in func:
                    pad_index = func['pskb']
                    skb_param = 'struct sk_buff **pskb'
                    bpf_prep = 'struct sk_buff *skb = *pskb;'
                else:
                    continue

                skb_params = ''
                for i in range(pad_index):
                    skb_params += 'void *arg_%d, ' % i
                skb_params += skb_param

                if TracePoint.is_ret_enabled(func):
                    ret_str = kretprobe_template % (
                        TracePoint.KRETPROBE_PREFIX, name, func_index,
                        NetUtils.b2str(TracePoint.is_clone(func)))
                else:
                    ret_str = ''

                ph_functions += kprobe_template % (TracePoint.KPROBE_PREFIX,
                                                   name, skb_params,
                                                   func_index, trace_params)
                ph_functions += ret_str
            ph_functions = ph_functions.replace('BPF_prep', bpf_prep)

        return ph_functions

    @staticmethod
    def get_func_by_index(index):
        return TracePoint._functions[index]

    @staticmethod
    def attach_item(bpf, item):
        if not TracePoint.is_valid(item):
            return False

        if TracePoint.is_tp(item):
            tp_info = item['tp'].split(':')
            if bcc.BPF.tracepoint_exists(tp_info[0], tp_info[1]):
                return True
            else:
                return False

        name = item['name']
        name_re = item.get('regex')
        kretprobe_name = '%s%s' % (TracePoint.KRETPROBE_PREFIX, name)
        kprobe_name = '%s%s' % (TracePoint.KPROBE_PREFIX, name)

        if name_re:
            bpf.attach_kprobe(event_re=name_re, fn_name=kprobe_name)
            if TracePoint.is_ret_enabled(item):
                bpf.attach_kretprobe(event_re=name_re, fn_name=kretprobe_name)
        else:
            if bpf.ksymname(name) < 0:
                return False
            bpf.attach_kprobe(event=name, fn_name=kprobe_name)
            if TracePoint.is_ret_enabled(item):
                bpf.attach_kretprobe(event=name, fn_name=kretprobe_name)

        return True

    @staticmethod
    def attach_all_item(bpf):
        for item in TracePoint._functions:
            if TracePoint.attach_item(bpf, item):
                item['attached'] = True
                if Helper.verbose_enabled():
                    print('attach %s success' % item['name'])
            else:
                item['attached'] = False
                if Helper.verbose_enabled():
                    Helper.pr_warn('attach %s failed' % item['name'])


class Helper:
    _output_fmt = {
        'id': '[%x]',
        'cpu': '[cpu:%03u]',
        'if': '[%-8s]',
        'pid': '[%-24s]',
        'module': '[%-12s]'
    }
    _user_args = {}

    @staticmethod
    def pr_warn(info):
        print('\nWARNING: %s' % info)

    @staticmethod
    def pr_err(info, do_exit=True):
        print('\nERROR: %s' % info)
        if do_exit:
            exit(-1)

    @staticmethod
    def check_stack():
        args = Helper.get_args()
        if not args.stack:
            return
        if not args.tracer or 'all' in args.tracer:
            if args.force_stack:
                return
            Helper.pr_warn('''Do you want to print stack for all tracer? If not, please special
a tracer by "-t". Otherwise, use "--force-stack" to print stack for all
tracer.

Notice: this may cause performance issue.\n''')
            exit(-1)

    @staticmethod
    def parse_args():
        parser = argparse.ArgumentParser()
        parser.add_argument('-s', '--saddr', help='ip source address')
        parser.add_argument('-d', '--daddr', help='ip dest address')
        parser.add_argument('--addr', help='ip source or dest address')
        parser.add_argument('-p', '--proto',
                            help='network protocol (L3 or L4) in lower case,'
                            ' such ip, tcp, udp, etc.')
        parser.add_argument('--dport', type=int, help='TCP/UDP dest port')
        parser.add_argument('--sport', type=int, help='TCP/UDP source port')
        parser.add_argument('--port', type=int,
                            help='TCP/UDP source or dest port')
        parser.add_argument('--tcp-flags',
                            help='TCP flags to filter, such as S(syn), A(ack), R(rst), etc')
        parser.add_argument('-t', '--tracer',
                            help='The network module or kernel function '
                            'to trace. Use "-t ?" to see available tracer')
        parser.add_argument('-o', '--output',
                            help='print extern info. options include: pid, if, id, cpu and module. '
                            'pid: process info; if: ifindex and ifname; id: memory address '
                            'of skb; cpu: the cpu id that run on; module: the network module of '
                            'the tracer belong to. multiple options should be splited by ","')
        parser.add_argument('--detail', action='store_true',
                            help='show all info for trace output, which means '
                            'enable all options in "--output"')
        parser.add_argument('--stack', action='store_true',
                            help='print kernel function call stack')
        parser.add_argument('--stack-tracer',
                            help='print kernel call stack for special tracer.')
        parser.add_argument('--force-stack', action='store_true',
                            help='force print stack for "all" tracer')
        parser.add_argument('--ret', action='store_true',
                            help='trace the return value')
        parser.add_argument('--timeline', action='store_true',
                            help='print skb on timeline')
        parser.add_argument('-c', '--count', type=int,
                            help='skb count to trace (timeline should be enabled)')
        parser.add_argument('--skb-mode', action='store_true',
                            help='keep tracing skb once it is matched')
        parser.add_argument('-v', '--verbose',
                            action='store_true', help='show more verbose info')
        return parser.parse_args()

    @staticmethod
    def init_args():
        args = Helper.parse_args()
        Helper._user_args = args

        if args.tracer == '?':
            print('available tracer:')
            print('---------------------------------------------------\n')
            TracePoint.print_tracer(TracePoint.get_all_tracer())
            print('\n---------------------------------------------------')
            exit(0)

        if args.count and not args.timeline:
            Helper.pr_err('"--timeline" should be enabled when "-c" is seted')

        if args.output:
            outputs = args.output.split(',')
            for o in outputs:
                if o not in Helper._output_fmt.keys():
                    Helper.pr_err('output option not found:%s' % o)
            args.output = outputs
            args.detail = 'cpu' in outputs or 'if' in outputs or 'pid' in outputs
        elif args.detail:
            args.output = Helper._output_fmt.keys()
        else:
            args.output = []

        Helper.check_stack()
        if os.geteuid() != 0:
            Helper.pr_err('Please run nettrace as root! Aborting...')

        return args

    @staticmethod
    def ret_enabled():
        return Helper._user_args.ret or Helper._user_args.timeline

    @staticmethod
    def verbose_enabled():
        return Helper._user_args.verbose

    @staticmethod
    def stack_enabled():
        return Helper._user_args.stack or Helper._user_args.stack_tracer

    @staticmethod
    def skb_mode_enabled():
        return Helper._user_args.skb_mode

    @staticmethod
    def get_tracer():
        return (Helper._user_args.tracer or 'all').split(',')

    @staticmethod
    def get_stack_tracer():
        return (Helper._user_args.stack_tracer or '').split(',')

    @staticmethod
    def get_count():
        return Helper._user_args.count

    @staticmethod
    def detail_enabled():
        return Helper._user_args.detail

    @staticmethod
    def id_enabled():
        args = Helper._user_args
        return args.skb_mode or args.ret or args.detail or 'id' in args.output

    @staticmethod
    def tl_enabled():
        return Helper._user_args.timeline

    @staticmethod
    def get_args():
        return Helper._user_args

    @staticmethod
    def get_output():
        return Helper._user_args.output


class Compile:
    _contxt = None
    _cflags = None

    @staticmethod
    def get_context():
        if Compile._contxt:
            return Compile._contxt

        class IP(ctypes.Structure):
            _fields_ = [
                ('saddr', ctypes.c_uint32),
                ('daddr', ctypes.c_uint32),
            ]

        class ARP_Ext(ctypes.Structure):
            _fields_ = [
                ('op', ctypes.c_uint16)
            ]

        class Tcp(ctypes.Structure):
            _fields_ = [
                ('sport', ctypes.c_uint16),
                ('dport', ctypes.c_uint16),
                ('seq', ctypes.c_uint32),
                ('ack', ctypes.c_uint32),
                ('flags', ctypes.c_uint8),
            ]

        class Udp(ctypes.Structure):
            _fields_ = [
                ('sport', ctypes.c_uint16),
                ('dport', ctypes.c_uint16),
            ]

        class Icmp(ctypes.Structure):
            _fields_ = [
                ('type', ctypes.c_uint8),
                ('code', ctypes.c_uint8),
                ('seq', ctypes.c_uint16),
                ('id', ctypes.c_uint16),
            ]

        class Field_l3(ctypes.Union):
            _fields_ = [
                ('ip', IP),
            ]

        class Field_l4(ctypes.Union):
            _fields_ = [
                ('tcp', Tcp),
                ('udp', Udp),
                ('icmp', Icmp),
                ('arp_ext', ARP_Ext),
            ]

        ctx_fields = [('ts', ctypes.c_uint64), ('field_l3', Field_l3),
                      ('ret_val', ctypes.c_uint64)]
        cflags = []

        if TracePoint.has_any_ret():
            cflags.append('-DNT_ENABLE_RET')
        if TracePoint.has_any_ret() or Helper.id_enabled():
            ctx_fields.append(('id', ctypes.c_uint64))
        if Helper.detail_enabled():
            ctx_fields.extend([
                ('ifname', ctypes.c_char * 16),
                ('ifindex', ctypes.c_uint32),
                ('comm', ctypes.c_char * 16),
                ('pid', ctypes.c_uint32),
                ('cpu', ctypes.c_uint32),
            ])
            cflags.append('-DNT_ENABLE_DETAIL')
        if Helper.stack_enabled():
            ctx_fields.append(('stack_id', ctypes.c_uint32))
            cflags.append('-DNT_ENABLE_STACK')
        if Helper.skb_mode_enabled():
            cflags.append('-DNT_ENABLE_SKB_MODE')

        ctx_fields += [
            ('field_l4', Field_l4),
            ('proto_l3', ctypes.c_uint16),
            ('proto_l4', ctypes.c_uint8),
            ('func', ctypes.c_uint8)
        ]

        if TracePoint.has_any_ret():
            ctx_fields.append(('is_ret', ctypes.c_uint8))

        class Context(ctypes.Structure):
            _fields_ = ctx_fields

        Compile._contxt = Context
        Compile._cflags = cflags
        return Context

    @staticmethod
    def get_cflags():
        if Compile._cflags is None:
            Compile.get_context()
        return Compile._cflags


class Output:

    _tl_table = {}
    _count = 0
    _stop = False

    @staticmethod
    def _print_stack(stack_id, tgid):
        stack_map = Core.get_bpf()['stacks']
        if stack_id < 0:
            return
        try:
            stack = list(stack_map.walk(stack_id))
        except Exception as e:
            return
        for addr in stack:
            print("        %s" % Core.get_bpf().sym(addr, tgid,
                  show_module=True, show_offset=True))

    @staticmethod
    def _generate_ip_info(ctx):
        ip = ctx.field_l3.ip
        output_str = ''

        if ctx.proto_l4 == socket.IPPROTO_TCP:
            tcp = ctx.field_l4.tcp
            output_str += 'TCP: %s:%d -> %s:%d, seq:%d, ack:%d %s' % (
                NetUtils.int2ip(socket.ntohl(ip.saddr)),
                socket.ntohs(tcp.sport),
                NetUtils.int2ip(socket.ntohl(ip.daddr)),
                socket.ntohs(tcp.dport),
                socket.ntohl(tcp.seq),
                socket.ntohl(tcp.ack),
                NetUtils.int2tcp_flags(tcp.flags))
        elif ctx.proto_l4 == socket.IPPROTO_UDP:
            udp = ctx.field_l4.udp
            output_str += 'UDP: %s:%d -> %s:%d' % (
                NetUtils.int2ip(socket.ntohl(ip.saddr)),
                socket.ntohs(udp.sport),
                NetUtils.int2ip(socket.ntohl(ip.daddr)),
                socket.ntohs(udp.dport))
        elif ctx.proto_l4 == socket.IPPROTO_ICMP:
            icmp = ctx.field_l4.icmp
            if icmp.type == NetUtils.ICMP_TYPE['ICMP_ECHOREPLY']:
                icmp_info = 'ping reply'
            elif icmp.type == NetUtils.ICMP_TYPE['ICMP_ECHO']:
                icmp_info = 'ping request'
            else:
                icmp_info = 'type: %d, code: %d' % (icmp.type, icmp.code)
            output_str += 'ICMP: %s -> %s, %-15s, seq: %d' % (
                NetUtils.int2ip(
                    socket.ntohl(ip.saddr)),
                NetUtils.int2ip(
                    socket.ntohl(ip.daddr)),
                icmp_info,
                socket.ntohs(icmp.seq))
        else:
            fmt = '%s: %s -> %s'
            output_str += fmt % (NetUtils.int2proto(socket.ntohs(ctx.proto_l3)),
                                 NetUtils.int2ip(socket.ntohl(ip.saddr)),
                                 NetUtils.int2ip(socket.ntohl(ip.daddr)))
        return output_str

    @staticmethod
    def _generate_arp_info(ctx):
        arp_ext = ctx.field_l4.arp_ext
        ip = ctx.field_l3.ip
        type = ''
        if socket.ntohs(arp_ext.op) == 1:
            type = 'request'
        elif socket.ntohs(arp_ext.op) == 2:
            type = 'reply'
        elif socket.ntohs(arp_ext.op) == 3:
            type = 'rarp request'
        elif socket.ntohs(arp_ext.op) == 4:
            type = 'rarp reply'
        fmt = 'ARP: %s -> %s, %s'
        return fmt % (NetUtils.int2ip(socket.ntohl(ip.saddr)),
                      NetUtils.int2ip(socket.ntohl(ip.daddr)),
                      type)

    @staticmethod
    def _generate_proto_info(ctx):
        proto_l3 = socket.ntohs(ctx.proto_l3)

        if proto_l3 == NetUtils.PROTO_L3['IP']:
            return Output._generate_ip_info(ctx)

        if proto_l3 == NetUtils.PROTO_L3['ARP']:
            return Output._generate_arp_info(ctx)

        output_str = '%s' % (NetUtils.int2proto(
            proto_l3, 3) or str(proto_l3))
        return output_str

    @staticmethod
    def _print_event(ctx):
        item = TracePoint.get_func_by_index(ctx.func)
        ts = float(ctx.ts)/1000000000

        output_fmt = Helper.get_output()
        d_info = ifname = p_info = ''
        if 'if' in output_fmt:
            ifname = ctx.ifname.decode(encoding='utf-8')
            if ifname:
                ifname = '%d:%s' % (ctx.ifindex, ifname)
            elif ctx.ifindex:
                try:
                    ifname = socket.if_indextoname(ctx.ifindex)
                    ifname = '%d:%s' % (ctx.ifindex, ifname)
                except Exception:
                    ifname = '%d' % ctx.ifindex
            ctx.__dict__['if'] = ifname
        if 'pid' in output_fmt:
            p_info = 'pid:%d,%s' % (ctx.pid, ctx.comm.decode(encoding='utf-8'))
            ctx.__dict__['pid'] = p_info
        ctx.__dict__['module'] = item['parent_str']

        for k in output_fmt:
            if k in ctx.__dict__:
                val = ctx.__dict__[k]
            else:
                val = getattr(ctx, k)
            d_info += Helper._output_fmt[k] % val

        output_str = '%f: %s[%-24s]: ' % (ts, d_info, item['name'])

        if TracePoint.is_ret_enabled(item) and ctx.is_ret:
            desc_info = 'return value:%x' % ctx.ret_val
        else:
            desc_info = ''

        output_str += Output._generate_proto_info(ctx)
        if desc_info:
            output_str = '%s\n%-16s%s' % (output_str, '', desc_info)
        print(output_str)
        item['stack'] and Output._print_stack(ctx.stack_id, -1)

    @staticmethod
    def _handle_timeline(ctx):
        item = TracePoint.get_func_by_index(ctx.func)
        queue = Output._tl_table.setdefault(ctx.id, {'refs': 1, 'items': []})
        queue['items'].append(ctx)
        if TracePoint.is_clone(item):
            new_skb = ctx.ret_val
            queue['refs'] += 1
            Output._tl_table[new_skb] = queue
            return

        if not TracePoint.is_end(item):
            return
        Output._tl_table.pop(ctx.id)
        queue['refs'] -= 1
        if queue['refs'] > 0:
            return
        print('<------------------- skb: %x ---------------------->' % ctx.id)
        items = queue['items']
        items.sort(key=lambda x: x.ts)
        for i in items:
            Output._print_event(i)
        print('')
        if not Helper.get_count():
            return
        Output._count += 1
        if Output._count >= Helper.get_count():
            Output._stop = True

    @staticmethod
    def _handle_event(cpu, data, size):
        ctx = ctypes.cast(data, ctypes.POINTER(Compile.get_context())).contents
        if Helper.tl_enabled():
            Output._handle_timeline(ctx)
        else:
            Output._print_event(ctx)

    @staticmethod
    def do_output():
        Core.get_bpf()['m_output'].open_perf_buffer(Output._handle_event)
        print('begin tracing......')
        while not Output._stop:
            try:
                Core.get_bpf().perf_buffer_poll()
            except KeyboardInterrupt:
                print('end tracing......')
                exit(0)


class Core:
    _bpf_ins = None

    @staticmethod
    def generate_bpf_code():
        # parse C code and return the text that parsed.
        with open(project_file('nettrace.c'), 'r') as f:
            bpf_text = f.read()

            ph_filter = []
            args = Helper.get_args()
            has_port = False
            has_ip = False
            if args.saddr:
                ph_filter.append('ctx->field_saddr == %d' %
                                 socket.htonl(NetUtils.ip2int(args.saddr)))
                has_ip = True
            if args.daddr:
                ph_filter.append('ctx->field_daddr == %d' %
                                 socket.htonl(NetUtils.ip2int(args.daddr)))
                has_ip = True
            if args.addr:
                addr = socket.htonl(NetUtils.ip2int(args.addr))
                ph_filter.append('(ctx->field_saddr == %d || ctx->field_daddr == %d)' %
                                 (addr, addr))
                has_ip = True
            if args.sport:
                ph_filter.append('ctx->field_sport == %d' %
                                 socket.htons(args.sport))
                has_port = True
            if args.dport:
                ph_filter.append('ctx->field_dport == %d' %
                                 socket.htons(args.dport))
                has_port = True
            if args.port:
                port = socket.htons(args.port)
                ph_filter.append('(ctx->field_dport == %d || ctx->field_sport == %d)' %
                                 (port, port))
                has_port = True

            if args.tcp_flags:
                flags = NetUtils.tcp_flags2int(args.tcp_flags)
                ph_filter.append(
                    '(ctx->field_flags & %d)' % socket.htons(flags))
                if not args.proto:
                    args.proto = 'tcp'
                elif args.proto != 'tcp':
                    Helper.pr_err(
                        'protocol (-p) should be "tcp" while "tcp-flags" is set')
            if args.proto:
                if has_port and args.proto not in ['tcp', 'udp']:
                    Helper.pr_err(
                        'protocol (-p) should be "tcp" or "udp" while port is set')
                proto, level = NetUtils.proto2int(args.proto)
                if proto is None:
                    Helper.pr_err('proto: %s not found!' % args.proto)
                if level == 3:
                    proto = socket.htons(proto)
                    if has_ip and args.proto not in ['ip', 'arp']:
                        Helper.pr_err(
                            'protocol (-p) should be "ip" while addr is set')
                else:
                    ph_filter.append('ctx->proto_l3 == htons(ETH_P_IP)')
                ph_filter.append('ctx->proto_l%d == %d' % (level, proto))
            elif has_port:
                p_udp, level = NetUtils.proto2int('udp')
                p_tcp, level = NetUtils.proto2int('tcp')
                ph_filter.append(
                    '(ctx->proto_l4 == %d || ctx->proto_l4 == %d)' % (p_udp, p_tcp))

            bpf_text = bpf_text.replace(
                'BPF_PH_filter', '&&'.join(ph_filter) or '1')
            ph_functions = TracePoint.generate_func_code()
            if not ph_functions:
                Helper.pr_err('no tracer found!')
            func_count = len(TracePoint._functions)
            bpf_text = bpf_text.replace('BPF_PH_count', str(func_count))
            bpf_text = bpf_text.replace('BPF_PH_function', ph_functions)
            return bpf_text

    @staticmethod
    def load_bpf():
        # generate BPF object and attach the C code to BPF.
        bpf_text = Core.generate_bpf_code()
        not bpf_text and exit(-1)

        bpf = bcc.BPF(text=bpf_text, cflags=Compile.get_cflags())
        Core._bpf_ins = bpf

        TracePoint.attach_all_item(bpf)
        if Helper.verbose_enabled():
            print('\nfollowing tracers are enabled:')
            print('-----------------------------------\n')
            for t in TracePoint._tracers:
                TracePoint.print_tracer(t)
            print('-----------------------------------\n')

    @staticmethod
    def get_bpf():
        return Core._bpf_ins

    @staticmethod
    def run():
        Helper.init_args()
        TracePoint.init_functions()
        Core.load_bpf()
        Output.do_output()


Core.run()
