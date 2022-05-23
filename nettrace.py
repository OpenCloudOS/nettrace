#!/usr/bin/python3
import argparse
import json
import socket
import ctypes
import re
import os
import yaml
import bcc

from utils import *


class Tracer:
    KPROBE_PREFIX = 'nettrace_kprobe__'
    KRETPROBE_PREFIX = 'nettrace_kretprobe__'
    TP_PREFIX = 'nettrace_tp__'
    TYPE_TRACEPOINT = 'tracepoint'
    TYPE_KPROBE = 'kprobe'
    TYPE_KRETPROBE = 'kretprobe'

    _tracer_enabled = []
    _cata_enabled = []
    _cata_all = None

    @staticmethod
    def get_cata_all():
        if Tracer._cata_all:
            return Tracer._cata_all
        with open(project_file('skb.yaml'), 'r') as f:
            data = f.read()
            cata = yaml.load(data, yaml.BaseLoader)
            Tracer._cata_all = cata
            f.close()
            Tracer.prepare_cata(cata)
            return cata

    @staticmethod
    def is_tracer(tracer):
        return 'children' not in tracer

    @staticmethod
    def is_tp(tracer):
        return tracer.get('type') == Tracer.TYPE_TRACEPOINT

    @staticmethod
    def is_ret_enabled(tracer):
        return tracer.get('ret_enabled')

    @staticmethod
    def is_valid(tracer):
        if Tracer.is_tp(tracer):
            return True
        if 'skb' not in tracer and 'pskb' not in tracer:
            return False
        return True

    @staticmethod
    def is_ret_only(tracer):
        return tracer.get('ret_only')

    @staticmethod
    def has_any_ret():
        for tracer in Tracer._tracer_enabled:
            if Tracer.is_ret_enabled(tracer):
                return True
        return False

    @staticmethod
    def is_end(tracer):
        return tracer.get('is_end')

    @staticmethod
    def is_clone(tracer):
        return tracer['name'] == 'skb_clone'

    @staticmethod
    def get_cata_or_tracer(name, root=None):
        if not root:
            root = Tracer.get_cata_all()
            if name == root['name']:
                return root
        for cata in root['children']:
            if cata['name'] == name:
                return cata
            elif not Tracer.is_tracer(cata):
                t = Tracer.get_cata_or_tracer(name, cata)
                if t:
                    return t
        return None

    @staticmethod
    def get_tracers(cata):
        result = []
        if not cata:
            return []
        if Tracer.is_tracer(cata):
            result.append(cata)
        else:
            for v in cata['children']:
                if Tracer.is_tracer(v):
                    result.append(v)
                else:
                    result += Tracer.get_tracers(v)
        return result

    @staticmethod
    def bind_parent(root):
        for i in root['children']:
            i['parent'] = root
            if Tracer.is_tracer(i):
                continue
            Tracer.bind_parent(i)

    @staticmethod
    def print_tracer(tracer, tab=''):
        if Tracer.is_tracer(tracer):
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
            Tracer.print_tracer(i, tab + '    ')

    @staticmethod
    def check_if(tracer):
        if 'if' not in tracer:
            return True
        cond = tracer['if']
        kernelVersion = kernel_version_cur()
        cond = cond.replace('kernelVersion', str(kernelVersion))
        ret = {'value': False}
        cond = '''value = %s''' % cond
        exec(cond, ret)
        return ret['value']

    @staticmethod
    def prepare_cata(root=None):
        if not root:
            root = Tracer.get_cata_all()
        if Tracer.is_tracer(root):
            return
        children = root['children']
        i = 0
        while i < len(children):
            c = children[i]
            if not isinstance(c, str):
                Tracer.prepare_cata(c)
                i += 1
                continue
            children.remove(c)
            data = c.split(':')
            if len(data) <= 1:
                c = {
                    "name": data[0]
                }
            else:
                c = {
                    "name": data[0],
                    "skb": int(data[1])
                }
            children.insert(i, c)
            i += 1

    @staticmethod
    def init_tracers():
        tracers, catalogs, stack_tracers = [], [], []
        for cata_str in set(Helper.get_tracer()):
            cata = Tracer.get_cata_or_tracer(cata_str)
            if not cata:
                Helper.pr_warn('the tracer:%s not found' % cata_str)
                continue
            for tracer in Tracer.get_tracers(cata):
                if Tracer.check_if(tracer):
                    tracers.append(tracer)
                else:
                    tracer['hidden'] = True
            catalogs.append(cata)

        for t in set(Helper.get_stack_tracer()):
            stack_tracers += Tracer.get_tracers(Tracer.get_cata_or_tracer(t))

        end_tracers = [i for i in tracers if i.get('is_end')]
        if not end_tracers and Helper.tl_enabled():
            cata = Tracer.get_cata_or_tracer('life')
            tracers += Tracer.get_tracers(cata)
            catalogs.append(cata)
            Helper.pr_warn('''no end tracer is found in timeline mode!
"life" tracer is enabled automatically
''')

        for f in tracers:
            if stack_tracers:
                if f in stack_tracers:
                    f['stack'] = True
                else:
                    f['stack'] = False
            elif Helper.get_args().stack:
                f['stack'] = True
            else:
                f['stack'] = False

        Tracer._tracer_enabled = tracers
        Tracer._cata_enabled = catalogs
        Tracer.bind_parent(Tracer.get_cata_all())

        for t in tracers:
            p = t['parent']
            parents = []
            while p and 'visual' in p:
                parents.append(p['name'])
                p = p.get('parent')
            t['parent_str'] = '->'.join(parents)
            if Helper.get_args().ret and not Tracer.is_tp(t):
                t['ret_enabled'] = True
            if Helper.tl_enabled() and Tracer.is_clone(t):
                t['ret_only'] = True
                t['ret_enabled'] = True

    @staticmethod
    def _generate_tracer_code(tracer, index):
        kprobe_template = '''int %s%s(struct pt_regs *regs, %s)
        { BPF_prep func_params_t param = {%s}; return do_trace(regs, skb, &param); }\n'''
        kretprobe_template = '''int %s%s(void *ctx)
        { return ret_trace(ctx, %d, %s); }\n'''
        tp_template = '''TRACEPOINT_PROBE(%s)
        { BPF_prep func_params_t param = {%s}; return do_trace(args, skb, &param); }\n'''

        code = ''
        param_code = '.func = %d,' % index

        ret_only = b2str(Tracer.is_ret_only(tracer))

        if Helper.ret_enabled():
            param_code += '.ret = %s, .ret_only = %s,' % (
                b2str(Tracer.is_ret_enabled(tracer)),
                ret_only)
        if Helper.stack_enabled():
            param_code += '.stack = %s,' % b2str(tracer['stack'])
        if Helper.skb_mode_enabled():
            param_code += '.is_end = %s,' % b2str(Tracer.is_end(tracer))
        param_code = param_code.strip(',')

        if Tracer.is_tp(tracer):
            tp_info = tracer['tp'].split(':')
            if not bcc.BPF.tracepoint_exists(tp_info[0], tp_info[1]):
                return
            tp_name = tracer['tp'].replace(':', ', ')
            code += tp_template % (tp_name, param_code)
            bpf_prep = 'struct sk_buff *skb = args->%s;' % tracer['skb']
        else:
            name = tracer['name']
            if 'regex' not in tracer and bcc.BPF.ksymname(name) < 0:
                return
            if 'skb' in tracer:
                pad_index = tracer['skb']
                skb_param = 'struct sk_buff *skb'
                bpf_prep = ''
            elif 'pskb' in tracer:
                pad_index = tracer['pskb']
                skb_param = 'struct sk_buff **pskb'
                bpf_prep = 'struct sk_buff *skb = *pskb;'
            else:
                return

            skb_params = ''
            for i in range(int(pad_index)):
                skb_params += 'void *arg_%d, ' % i
            skb_params += skb_param

            if Tracer.is_ret_enabled(tracer):
                ret_str = kretprobe_template % (
                    Tracer.KRETPROBE_PREFIX, name, index,
                    ret_only)
            else:
                ret_str = ''

            code += kprobe_template % (Tracer.KPROBE_PREFIX,
                                       name, skb_params, param_code)
            code += ret_str
        code = code.replace('BPF_prep', bpf_prep)

        return code

    @staticmethod
    def generate_code():
        code = ''
        for func_index in range(len(Tracer._tracer_enabled)):
            func = Tracer._tracer_enabled[func_index]
            if not Tracer.is_valid(func):
                continue
            tracer_code = Tracer._generate_tracer_code(func, func_index)
            if not tracer_code:
                continue
            code += tracer_code
        return code

    @staticmethod
    def get_tracer_by_index(index):
        return Tracer._tracer_enabled[index]

    @staticmethod
    def attach_tracer(tracer):
        if not Tracer.is_valid(tracer):
            return False

        if Tracer.is_tp(tracer):
            tp_info = tracer['tp'].split(':')
            if bcc.BPF.tracepoint_exists(tp_info[0], tp_info[1]):
                return True
            else:
                return False

        name = tracer['name']
        name_re = tracer.get('regex')
        kretprobe_name = '%s%s' % (Tracer.KRETPROBE_PREFIX, name)
        kprobe_name = '%s%s' % (Tracer.KPROBE_PREFIX, name)
        bpf = Core.get_bpf()

        if name_re:
            bpf.attach_kprobe(event_re=name_re, fn_name=kprobe_name)
            if Tracer.is_ret_enabled(tracer):
                bpf.attach_kretprobe(event_re=name_re, fn_name=kretprobe_name)
        else:
            if bpf.ksymname(name) < 0:
                return False
            bpf.attach_kprobe(event=name, fn_name=kprobe_name)
            if Tracer.is_ret_enabled(tracer):
                bpf.attach_kretprobe(event=name, fn_name=kretprobe_name)

        return True

    @staticmethod
    def attach_all():
        for tracer in Tracer._tracer_enabled:
            if Tracer.attach_tracer(tracer):
                tracer['attached'] = True
                if Helper.verbose_enabled():
                    print('attach %s success' % tracer['name'])
            else:
                tracer['attached'] = False
                if Helper.verbose_enabled():
                    Helper.pr_warn('attach %s failed' % tracer['name'])


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
            args.tracer = 'all'
            Tracer.init_tracers()
            print('available tracer:')
            print('---------------------------------------------------\n')
            Tracer.print_tracer(Tracer.get_cata_all())
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

        class IPV6(ctypes.Structure):
            _fields_ = [
                ('saddr', ctypes.c_uint16*8),
                ('daddr', ctypes.c_uint16*8),
            ]

        class ArpExt(ctypes.Structure):
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

        class FieldL3(ctypes.Union):
            _fields_ = [
                ('ip', IP),
                ('ipv6', IPV6),
            ]

        class FieldL4(ctypes.Union):
            _fields_ = [
                ('tcp', Tcp),
                ('udp', Udp),
                ('icmp', Icmp),
                ('arp_ext', ArpExt),
            ]

        ctx_fields = [('ts', ctypes.c_uint64), ('field_l3', FieldL3)]
        cflags = []

        if Tracer.has_any_ret():
            ctx_fields.append(('ret_val', ctypes.c_uint64))
            cflags.append('-DNT_ENABLE_RET')
        if Tracer.has_any_ret() or Helper.id_enabled():
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
            ('field_l4', FieldL4),
            ('proto_l3', ctypes.c_uint16),
            ('func', ctypes.c_uint16),
            ('proto_l4', ctypes.c_uint8)
        ]

        if Tracer.has_any_ret():
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
        stack = list(stack_map.walk(stack_id))
        for addr in stack:
            print("        %s" % Core.get_bpf().sym(addr, tgid,
                  show_module=True, show_offset=True))

    @staticmethod
    def _generate_ip_info(ctx, is_ipv6=False):
        output_str = ''

        if not is_ipv6:
            ip = ctx.field_l3.ip
            saddr = NetUtils.int2ip(socket.ntohl(ip.saddr))
            daddr = NetUtils.int2ip(socket.ntohl(ip.daddr))
        else:
            ip = ctx.field_l3.ipv6
            saddr = NetUtils.int2ipv6(ip.saddr)
            daddr = NetUtils.int2ipv6(ip.daddr)

        if ctx.proto_l4 == socket.IPPROTO_TCP:
            tcp = ctx.field_l4.tcp
            output_str += 'TCP: %s:%d -> %s:%d, seq:%d, ack:%d %s' % (
                saddr,
                socket.ntohs(tcp.sport),
                daddr,
                socket.ntohs(tcp.dport),
                socket.ntohl(tcp.seq),
                socket.ntohl(tcp.ack),
                NetUtils.int2tcp_flags(tcp.flags))
        elif ctx.proto_l4 == socket.IPPROTO_UDP:
            udp = ctx.field_l4.udp
            output_str += 'UDP: %s:%d -> %s:%d' % (
                saddr,
                socket.ntohs(udp.sport),
                daddr,
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
                saddr,
                daddr,
                icmp_info,
                socket.ntohs(icmp.seq))
        else:
            fmt = '%s: %s -> %s'
            output_str += fmt % (NetUtils.int2proto(socket.ntohs(ctx.proto_l3), 4),
                                 saddr,
                                 daddr)
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

        if proto_l3 == NetUtils.PROTO_L3['IPV6']:
            return Output._generate_ip_info(ctx, True)

        if proto_l3 == NetUtils.PROTO_L3['ARP']:
            return Output._generate_arp_info(ctx)

        output_str = '%s' % (NetUtils.int2proto(
            proto_l3, 3) or str(proto_l3))
        return output_str

    @staticmethod
    def _print_event(ctx):
        tracer = Tracer.get_tracer_by_index(ctx.func)
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
                except OSError:
                    ifname = '%d' % ctx.ifindex
            ctx.__dict__['if'] = ifname
        if 'pid' in output_fmt:
            p_info = 'pid:%d,%s' % (ctx.pid, ctx.comm.decode(encoding='utf-8'))
            ctx.__dict__['pid'] = p_info
        ctx.__dict__['module'] = tracer['parent_str']

        for k in output_fmt:
            if k in ctx.__dict__:
                val = ctx.__dict__[k]
            else:
                val = getattr(ctx, k)
            d_info += Helper._output_fmt[k] % val

        tracer_symbol = '  '
        desc_info = ''
        if Tracer.is_ret_enabled(tracer):
            if ctx.is_ret:
                desc_info = 'return value:%x' % ctx.ret_val
                if not Tracer.is_ret_only(tracer):
                    tracer_symbol = '<<'
            else:
                tracer_symbol = '>>'

        output_str = '%f: %s[%-24s %s]: ' % (ts, d_info, tracer['name'],
                                             tracer_symbol)
        output_str += Output._generate_proto_info(ctx)
        if desc_info:
            output_str = '%s\n%-16s%s' % (output_str, '', desc_info)
        print(output_str)
        tracer['stack'] and Output._print_stack(ctx.stack_id, -1)

    @staticmethod
    def _handle_skb_dead(shared, ctx):
        Output._tl_table.pop(ctx.id)
        shared['refs'] -= 1
        if shared['refs'] > 0:
            return
        print('<------------------- skb: %x ---------------------->' % ctx.id)
        tracers = shared['tracers']
        tracers.sort(key=lambda x: x.ts)
        for i in tracers:
            Output._print_event(i)
        print('')
        if not Helper.get_count():
            return
        Output._count += 1
        if Output._count >= Helper.get_count():
            Output._stop = True

    @staticmethod
    def _handle_timeline(ctx):
        tracer = Tracer.get_tracer_by_index(ctx.func)
        data = Output._tl_table.setdefault(ctx.id, {'refs': 0, 'shared': {
            'refs': 1, 'tracers': []
        }, 'dead': False})
        shared = data['shared']
        shared['tracers'].append(ctx)
        if Tracer.is_clone(tracer) and ctx.ret_val:
            shared['refs'] += 1
            Output._tl_table[ctx.ret_val] = {
                'refs': 0, 'shared': shared, 'dead': False
            }
            return

        if Tracer.is_ret_enabled(tracer):
            if ctx.is_ret:
                data['refs'] -= 1
            else:
                data['refs'] += 1

            if data['dead'] and not data['refs']:
                Output._handle_skb_dead(shared, ctx)
                return

        if not Tracer.is_end(tracer):
            return

        if Tracer.is_ret_enabled(tracer) and not ctx.is_ret:
            return
        data['dead'] = True
        if not data['refs']:
            Output._handle_skb_dead(shared, ctx)

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
            ph_functions = Tracer.generate_code()
            if not ph_functions:
                Helper.pr_err('no tracer found!')
            func_count = len(Tracer._tracer_enabled)
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

        Tracer.attach_all()
        if Helper.verbose_enabled():
            print('\nfollowing tracers are enabled:')
            print('-----------------------------------\n')
            for t in Tracer._cata_enabled:
                Tracer.print_tracer(t)
            print('-----------------------------------\n')

    @staticmethod
    def get_bpf():
        return Core._bpf_ins

    @staticmethod
    def run():
        Helper.init_args()
        Tracer.init_tracers()
        Core.load_bpf()
        Output.do_output()


Core.run()
