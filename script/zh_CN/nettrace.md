# NETTRACE 8 "20 JULY 2022" Linux "User Manuals"

## NAME

nettrace - Linux系统下的网络报文跟踪、网络问题诊断工具

## SYNOPSIS

`nettrace` [选项]

## DESCRIPTION

`nettrace`是基于eBPF的集网络报文跟踪（故障定位）、网络故障诊断、网络异常监控于一体的网
络工具集，旨在能够提供一种更加高效、易用的方法来解决复杂场景下的网络问题。

## OPTIONS

`-s,--saddr` *source_address*
  根据IP源地址来进行报文筛选

`-d,--daddr` *dest_address*
  根据IP目的地址来进行报文筛选

`--addr` *address*
  根据IP源地址或者目的地址来进行报文筛选

`-S,--sport` *source_port*
  根据UDP/TCP源端口进行报文筛选

`-D,--dport` *dest_port*
  根据UDP/TCP目的端口进行报文筛选

`--port` *port*
  根据UDP/TCP源端口或者目的端口进行报文筛选

`-p,--proto` *protocol*
  根据报文的协议（三层或者四层）进行过滤，如*-p udp*

`--netns` *netns_inode*
  根据网络命名空间进行过滤。
  
  该参数后面跟的是网络命名空间的inode，可以通过
  `ls -l /proc/<pid>/ns/net`
  来查看对应进程的网络命名空间的inode号

`--netns-current`
  仅显示当前网络命名空间的报文，等价于`--netns <当前网络命名空间的inode>`

`--pid` *pid*
  根据进程号进行过滤

`-t,--trace` *traces*
  要启用（跟踪）的内核函数、tracepoint。

  这里将这些被跟踪的对象（内核函数、tracepoint等）简称为跟踪器，
  所有的跟踪器以树状图的方式被组织了起来，使用命令：
  *nettrace -t ?*
  可以查看所有的跟踪器。

  默认情况下，大部分的跟踪器会被启用，一些设备相关的跟踪器（如ipvlan、bridge等）默认
  不启用。使用参数*-t all*可启用所有的跟踪器。

  可以同时指定多个跟踪器，以*,*分隔，比如*nettrace -t ip,link,kfree_skb*。
  可以指定跟踪器的目录，也可以直接指定跟踪器。

`--ret`
  显示被跟踪的内核函数的返回值

`--detail`
  显示跟踪详细信息，包括当前的进程、网口和CPU等信息

`--date`
  以时间格式打印（以2022-10-24 xx:xx:xx.xxxxxx格式打印），而不是时间戳

`--basic`
  启用`basic`跟踪模式。默认情况下，启用的是生命周期跟踪模式。启用该模式后，会直接打印
  出报文所经过的内核函数/tracepoint

`--diag`
  启用诊断模式

`--diag-quiet`
  只显示出现存在问题的报文，不显示正常的报文

`--diag-keep`
  持续跟踪。`diag`模式下，默认在跟踪到异常报文后会停止跟踪，使用该参数后，会持续跟踪下去。

`--sock`
  启用套接口模式。这个模式下，不会再跟踪报文，而会跟踪套接口。

`--monitor`
  启用监控模式。一种轻量化的实时监控系统中网络异常的模式（对内核版本有一定要求）。

`--hooks`
  打印netfilter上的钩子函数

`--drop`
  进行系统丢包监控，取代原先的`droptrace`

`--drop-stack`
  打印kfree_skb内核函数的调用堆栈，等价于`--trace-stack kfree_skb`

`--min-latency` *latency in ms*
  根据报文的寿命进行过滤，仅打印处理时长超过该值的报文，单位为ms。该参数仅在默认和`diag`模式下可用。

`--trace-stack` *traces*
  指定需要进行堆栈打印的内核函数，可以指定多个，用“,”分隔。出于性能考虑，启用堆栈打印的
  内核函数不能超过16个。用法和格式与`--trace`完全一致。

`-v`
  显示程序启动的日志信息

`--debug`
  显示调试信息

## EXAMPLES

### 生命周期跟踪

跟踪源地址为`192.168.1.8`的ping报文：
  *nettrace -p icmp -s 192.168.1.8*

跟踪源地址为`192.168.1.8`的ping报文在IP协议层和ICMP协议层的路径：
  *nettrace -p icmp -s 192.168.1.8 -t ip,icmp*

显示详细信息：
  *nettrace -p icmp -s 192.168.1.8 --detail*

打印堆栈：
  *nettrace -p icmp -s 192.168.1.8 --trace-stack consume_skb,icmp_rcv*

### 诊断模式

使用方式与上面的一致，加个`diag`参数即可使用诊断模式。上文的生命周期模式对于使用者的
要求比较高，需要了解内核协议栈各个函数的用法、返回值的意义等，易用性较差。诊断模式是在
生命周期模式的基础上，提供了更加丰富的信息，使得没有网络开发经验的人也可进行复杂
网络问题的定位和分析。

比于普通模式，诊断模式提供了更多的可供参考的信息，包括当前报文经过了iptables的哪些表和
哪些链、报文发生了NAT、报文被克隆了等。诊断模式设置了三种提示级别：

- `INFO`：正常的信息提示
- `WARN`：警告信息，该报文可能存在一定的问题，需要关注
- `ERROR`：异常信息，报文发生了问题（比如被丢弃）。

如果当前报文存在`ERROR`，那么工具会给出一定的诊断修复建议，并终止当前诊断操作。通过添
加`diag-keep`可以在发生`ERROR`事件时不退出，继续进行跟踪分析。下面是发生异常时的日志：

```shell
./nettrace -p icmp --diag --saddr 192.168.122.8
begin trace...
***************** ffff889fb3c64f00 ***************
[4049.295546] [__netif_receive_skb_core] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[4049.295566] [nf_hook_slow        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *ipv4 in chain: PRE_ROUTING*
[4049.295578] [nft_do_chain        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *iptables table:nat, chain:PREROUT* *packet is accepted*
[4049.295594] [nf_hook_slow        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *bridge in chain: PRE_ROUTING*
[4049.295612] [__netif_receive_skb_core] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[4049.295624] [ip_rcv              ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[4049.295629] [ip_rcv_core         ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[4049.295640] [nf_hook_slow        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *ipv4 in chain: PRE_ROUTING*
[4049.295644] [ip_rcv_finish       ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[4049.295655] [ip_route_input_slow ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[4049.295664] [fib_validate_source ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[4049.295683] [ip_forward          ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[4049.295687] [nf_hook_slow        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *ipv4 in chain: FORWARD* *packet is dropped by netfilter (NF_DROP)*
[4049.295695] [nft_do_chain        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *iptables table:filter, chain:FORWARD* *packet is dropped by iptables/iptables-nft*
[4049.295711] [kfree_skb           ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *packet is dropped by kernel*
---------------- ANALYSIS RESULT ---------------------
[1] ERROR happens in nf_hook_slow(netfilter):
        packet is dropped by netfilter (NF_DROP)
    fix advice:
        check your netfilter rule

[2] ERROR happens in nft_do_chain(netfilter):
        packet is dropped by iptables/iptables-nft
    fix advice:
        check your iptables rule

[3] ERROR happens in kfree_skb(life):
        packet is dropped by kernel
    location:
        nf_hook_slow+0x96
    drop reason:
        NETFILTER_DROP

analysis finished!

end trace...
```

从这里的日志可以看出，在报文经过iptables的filter表的forward链的时候，发生了丢包。在
诊断结果里，会列出所有的异常事件，一个报文跟踪可能会命中多条诊断结果。这里的诊断建议是让
用户检查iptables中的规则是否存在问题。

其中，`kfree_skb`这个跟踪点是对`drop reason`内核特性（详见droptrace中的介绍）做了
适配的，可以理解为将droptrace的功能集成到了这里的诊断结果中，这里可以看出其给出的丢包
原因是`NETFILTER_DROP`。因此，可以通过一下命令来监控内核中所有的丢包事件以及丢包原因：

*nettrace -t kfree_skb --diag --diag-keep*

### 丢包监控

使用命令`nettrace --drop`可以对系统中的丢包事件进行监控，对于支持内核特性
`skb drop reason`的内核，这里还会打印出丢包原因。可以通过查看
`/tracing/events/skb/kfree_skb/format`来判断当前系统是否支持该特性。

该模式下使用的效果与原先的`droptrace`完全相同，如下所示：

```shell
nettrace --drop
begin trace...
[142.097193] TCP: 162.241.189.135:57022 -> 172.27.0.6:22 seq:299038593, ack:3843597961, flags:AR, reason: NOT_SPECIFIED, tcp_v4_rcv+0x81
[142.331798] TCP: 162.241.189.135:57022 -> 172.27.0.6:22 seq:299038593, ack:3843597961, flags:A, reason: NOT_SPECIFIED, tcp_v4_do_rcv+0x83
[142.331857] TCP: 162.241.189.135:57022 -> 172.27.0.6:22 seq:299038593, ack:3843597961, flags:AP, reason: NOT_SPECIFIED, tcp_v4_do_rcv+0x83
[146.136576] TCP: 127.0.0.1:43582 -> 127.0.0.1:9999 seq:3819454691, ack:0, flags:S, reason: NO_SOCKET, tcp_v4_rcv+0x81
[146.220414] TCP: 169.254.0.138:8186 -> 172.27.0.6:40634 seq:8486084, ack:2608831141, flags:A, reason: TCP_INVALID_SEQUENCE, tcp_validate_incoming+0x126
[146.533728] TCP: 127.0.0.1:36338 -> 127.0.0.1:56100 seq:1110580666, ack:1951926207, flags:A, reason: TCP_INVALID_SEQUENCE, tcp_validate_incoming+0x126
[147.255946] TCP: 20.44.10.122:443 -> 192.168.255.10:42878 seq:2950381253, ack:211751623, flags:A, reason: NOT_SPECIFIED, tcp_rcv_state_process+0xe9
```

同样可以使用`man dropreason`命令来查看对应的丢包原因的详细解释。对于不支持
`skb drop reason`特性的内核，该模式下将不会打印丢包原因字段，效果如下所示：

```shell
nettrace --drop
begin trace...
[2016.965295] TCP: 162.241.189.135:45432 -> 172.27.0.6:22 seq:133152310, ack:2529234288, flags:AR, tcp_v4_rcv+0x50
[2017.201315] TCP: 162.241.189.135:45432 -> 172.27.0.6:22 seq:133152310, ack:2529234288, flags:A, tcp_v4_do_rcv+0x70
[2019.041344] TCP: 176.58.124.134:37441 -> 172.27.0.6:443 seq:1160140493, ack:0, flags:S, tcp_v4_rcv+0x50
[2021.867340] TCP: 127.0.0.1:34936 -> 127.0.0.1:9999 seq:1309795878, ack:0, flags:S, tcp_v4_rcv+0x50
[2024.997146] TCP: 162.241.189.135:46756 -> 172.27.0.6:22 seq:1304582308, ack:1354418612, flags:AR, tcp_v4_rcv+0x50
[2025.235953] TCP: 162.241.189.135:46756 -> 172.27.0.6:22 seq:1304582308, ack:1354418612, flags:A, tcp_v4_do_rcv+0x70
[2025.235967] TCP: 162.241.189.135:46756 -> 172.27.0.6:22 seq:1304582308, ack:1354418612, flags:AP, tcp_v4_do_rcv+0x70
```

### netfilter支持

网络防火墙是网络故障、网络不同发生的重灾区，因此`netfilter`工具对`netfilter`提供了
完美适配，包括老版本的`iptables-legacy`和新版本的`iptables-nft`。诊断模式下，
`nettrace`能够跟踪报文所经过的`iptables`表和`iptables`链，并在发生由于iptables
导致的丢包时给出一定的提示，上面的示例充分展现出了这部分。出了对iptables的支持，
`nettrace`对整个netfilter大模块也提供了支持，能够显示在经过每个HOOK点时对应的协议族
和链的名称。除此之外，为了应对一些注册到netfilter中的第三方内核模块导致的丢包问题，
`nettrace`还可以通过添加参数`hooks`来打印出当前`HOOK`上所有的的钩子函数，从而深入
分析问题：

```shell
./nettrace -p icmp --diag --saddr 192.168.122.8 --hooks
begin trace...
***************** ffff889faa054500 ***************
[5810.702473] [__netif_receive_skb_core] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 943
[5810.702491] [nf_hook_slow        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 943 *ipv4 in chain: PRE_ROUTING*
[5810.702504] [nft_do_chain        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 943 *iptables table:nat, chain:PREROUT* *packet is accepted*
[5810.702519] [nf_hook_slow        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 943 *bridge in chain: PRE_ROUTING*
[5810.702527] [__netif_receive_skb_core] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 943
[5810.702535] [ip_rcv              ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 943
[5810.702540] [ip_rcv_core         ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 943
[5810.702546] [nf_hook_slow        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 943 *ipv4 in chain: PRE_ROUTING*
[5810.702551] [ip_rcv_finish       ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 943
[5810.702556] [ip_route_input_slow ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 943
[5810.702565] [fib_validate_source ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 943
[5810.702579] [ip_forward          ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 943
[5810.702583] [nf_hook_slow        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 943 *ipv4 in chain: FORWARD* *packet is dropped by netfilter (NF_DROP)*
[5810.702586] [nft_do_chain        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 943 *iptables table:filter, chain:FORWARD* *packet is dropped by iptables/iptables-nft*
[5810.702599] [kfree_skb           ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 943 *packet is dropped by kernel*
---------------- ANALYSIS RESULT ---------------------
[1] ERROR happens in nf_hook_slow(netfilter):
        packet is dropped by netfilter (NF_DROP)

    following hook functions are blamed:
        nft_do_chain_ipv4

    fix advice:
        check your netfilter rule

[2] ERROR happens in nft_do_chain(netfilter):
        packet is dropped by iptables/iptables-nft
    fix advice:
        check your iptables rule

[3] ERROR happens in kfree_skb(life):
        packet is dropped by kernel
    location:
        nf_hook_slow+0x96
    drop reason:
        NETFILTER_DROP

analysis finished!

end trace...
```

可以看出，上面`following hook functions are blamed`中列出了导致当前`netfilter`
丢包的所有的钩子函数，这里只有`iptables`一个钩子函数。

### sock跟踪

套接口跟踪在原理上与skb的basic模式很类似，只不过跟踪对象从skb换成了sock。
常规的过滤参数，如ip、端口等，在该模式下都可以直接使用，基本用法如下所示：

```shell
sudo ./nettrace -p tcp --port 9999 --sock
begin trace...
[2157947.050509] [inet_listen         ] TCP: 0.0.0.0:9999 -> 0.0.0.0:0 info:(0 0)
[2157958.364842] [__tcp_transmit_skb  ] TCP: 127.0.0.1:36562 -> 127.0.0.1:9999 info:(1 0)
[2157958.364875] [tcp_rcv_state_process] TCP: 0.0.0.0:9999 -> 0.0.0.0:0 info:(0 0)
[2157958.364890] [tcp_rcv_state_process] TCP: 127.0.0.1:36562 -> 127.0.0.1:9999 info:(1 0) timer:(retrans, 1.000s)
[2157958.364896] [tcp_ack             ] TCP: 127.0.0.1:36562 -> 127.0.0.1:9999 info:(1 0) timer:(retrans, 1.000s)
[2157958.364906] [__tcp_transmit_skb  ] TCP: 127.0.0.1:36562 -> 127.0.0.1:9999 info:(0 0)
[2157958.364917] [tcp_rcv_state_process] TCP: 127.0.0.1:9999 -> 127.0.0.1:36562 info:(0 0)
[2157958.364921] [tcp_ack             ] TCP: 127.0.0.1:9999 -> 127.0.0.1:36562 info:(0 0)
[2157959.365240] [tcp_write_timer_handler] TCP: 127.0.0.1:36562 -> 127.0.0.1:9999 info:(0 0)
```

其中，`info`里显示的内容分别是：报文在外数量、报文重传数量。`timer`显示的为当前套接口上的定时器和超时时间。目前，信息还在不断完善中。

### monitor模式

常规的网络定位手段，包括上面的报文跟踪、诊断等方式，由于开销过大，不适合在生产环境中
部署和常态化运行。监控模式能够提供一种更加轻量级别的网络异常、丢包监控。由于这种模式
是基于`TRACING`类型的BPF，因此其对于内核版本有较高的要求。以下是内核版本要求：

|  TencentOS | 开源版本 | BPF特性 | monitor |
|---|---|---|---|
|5.4.119-19.0009 | 5.5 | TRACING | 可用，不可监控内核模块中的函数和参数个数超过6的内核函数 |
| 开发中 | 5.11 | BTF_MODULES | 可用，不可监控参数个数超过6的内核函数 |
| 开发中 | 开发中 | TRACING支持6+参数 | 完全可用 |

其中，“TRACING支持6+参数”目前正在开发中，具体进展可参见：

[bpf, x86: allow function arguments up to 12 for TRACING](https://lore.kernel.org/bpf/20230607125911.145345-1-imagedong@tencent.com/)

基本用法（在内核特性完全支持的情况下）：

```shell
$ nettrace --monitor
begin trace...
[25.167980] [nft_do_chain        ] ICMP: 192.168.122.1 -> 192.168.122.9 ping request, seq: 1, id: 1523 *iptables table:filter, chain:INPUT* *packet is dropped by iptables/iptables-nft*
[25.167996] [kfree_skb           ] ICMP: 192.168.122.1 -> 192.168.122.9 ping request, seq: 1, id: 1523, reason: NETFILTER_DROP, nf_hook_slow+0xa8
[25.168000] [nf_hook_slow        ] ICMP: 192.168.122.1 -> 192.168.122.9 ping request, seq: 1, id: 1523 *ipv4 in chain: INPUT* *packet is dropped by netfilter (NF_DROP)*
```

监控模式下，也可以使用普通模式的下各种参数，如报文过滤、`--detail`详情显示等。

## REQUIREMENTS

内核需要支持`CONFIG_BPF`, `CONFIG_KPROBE`, `CONFIG_DEBUG_INFO_BTF`(可选)功能

## OS

Linux

## AUTHOR

Menglong Dong

## SEE ALSO

nettrace-legacy(8), dropreason(8)

