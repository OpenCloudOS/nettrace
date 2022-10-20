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

`--basic`
  启用`basic`跟踪模式。默认情况下，启用的是生命周期跟踪模式。启用该模式后，会直接打印
  出报文所经过的内核函数/tracepoint

`--diag`
  启用诊断模式

`--diag-quiet`
  只显示出现存在问题的报文，不显示正常的报文

`--diag-keep`
  持续跟踪。`diag`模式下，默认在跟踪到异常报文后会停止跟踪，使用该参数后，会持续跟踪下去。

`--hooks`
  打印netfilter上的钩子函数

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

## REQUIREMENTS

内核需要支持CONFIG_BPF, CONFIG_KPROBE功能

## OS

Linux

## AUTHOR

Menglong Dong

## SEE ALSO

nettrace-legacy(8)
