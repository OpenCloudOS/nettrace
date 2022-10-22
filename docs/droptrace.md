# 丢包监控工具 - droptrace

## 一、背景

### 1.1 丢包的历史

网络丢包是网络故障排查中一个不朽的问题。很多网络故障的对外表现即为“丢包”，而所谓的“丢包”指的是报文没有按照预期到达报文的接收方。在Linux网络环境中，丢包发生的位置无非是在物理链路（即中间物理设备）和操作系统（即Linux内核）。其中我们遇到的大部分的丢包问题都是发生在内核中，因此理解内核为什么会做出“丢包”这一行为对我们解决网络故障尤为重要。

关于内核丢包这一方向的探索和实现，最早可以追溯到2009年的2.6.30版本内核。在该版本之前，内核还没有“丢包”的概念，即所有到报文释放都是通过统一的函数`kfree_skb()`来进行的，这种情况下用户（甚至是系统本身）是不知道报文是正常还是异常释放了的，即没有一个界限来区别“好的”和“坏的“报文。在2.6.30版本中，`Neil Horman`引入了`consume_skb()`接口，划清了丢包的界限：`kfree_skb()`用来丢包，`consume_skb()`用来正常释放报文。同时，他还定义了`kfree_skb`和`consume_skb`两个tracepoint，使得用户可以通过采集`kfree_skb`事件来监控系统上的丢包。为了向用户提供更丰富的丢包信息（如被丢弃的报文的内容），`Neil Horman`还引入了`drop monitor`模块，该功能可以通过`netlink`的方式将丢包事件传递给用户态程序。

### 1.2 dopwatch

`drop monitor`本质上是基于`kfree_skb`事件的，因此它提供的信息我们可以从`kfree_skb`事件中看的出来：通过`skb`的地址（skbaddr），它可以将报文的内容传给用户；通过指令地址（location，即调用`kfree_skb()`函数的地方），它可以告诉用户丢包发生的函数。

```shell
# cat /tracing/events/skb/kfree_skb/format 
name: kfree_skb
ID: 1408
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:void * skbaddr;   offset:8;       size:8; signed:0;
        field:void * location;  offset:16;      size:8; signed:0;
        field:unsigned short protocol;  offset:24;      size:2; signed:0;

print fmt: "skbaddr=%p protocol=%u location=%p", REC->skbaddr, REC->protocol, REC->location
```

`drop monitor`所提供的的信息对于我们定位网络丢包问题很有用，[dropwatch](https://github.com/nhorman/dropwatch)就是基于该功能实现的丢包监控工具。事实上，这个工具的作者好像正是`Neil Horman`本人。使用该工具，我们可以获取到以下的监控信息：

```shell
drop at: tcp_v4_rcv+0x86/0xf60 (0xffffffff81d5fbf6)
origin: software
input port ifindex: 2
timestamp: Fri May 27 17:18:02 2022 712681502 nsec
protocol: 0x800
length: 54
original length: 54
```

这个工具告诉了我们丢包发生的函数为`tcp_v4_rcv()`，收包的网口的index为2等信息。通过使用该工具提供的另一个命令dwdump，还可以把报文信息dump到pcap文件，使用wireshark等工具打开分析。然而这里有个问题：虽然我们已经把丢包定位到了具体的函数，知道了报文是在TCP层收包阶段被丢弃的，缩小了问题的范围，但是仍然不知道具体的丢包原因，因为`tcp_v4_rcv()`函数无论是什么原因导致丢包，都会跳转（goto）到统一的地方释放报文。整个内核协议栈在设计方面，采用了类似于”集中释放“的方式，即某项检查失败时不会直接在当前位置释放报文，而是返回一个错误码，并在某个调用的地方统一释放。这就使得在很多使用，我们并不能通过报文释放的位置来准确找到丢包的原因。

### 1.3 dropreason

为了解决上文中提到的问题，内核需要提供一种更加直观的机制来告诉用户为什么发生了丢包。为此，笔者也做了多方面的探索，最初的思路是为`snmp`增加一个的tracepoint点。`snmp`大家应该比较清楚，即内核提供的报文（网络）统计功能，通过命令`cat /proc/net/snmp`可以获取到当前系统的统计信息：

```
Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates
Ip: 1 64 1523807 0 1 0 0 0 1523802 1492568 0 40 0 0 0 0 0 0 0
Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps
Icmp: 117377 9 0 40 0 0 0 0 117336 0 1 0 0 0 117501 0 164 0 0 0 0 0 117336 0 1 0 0
IcmpMsg: InType3 InType8 InType13 OutType0 OutType3 OutType14
IcmpMsg: 40 117336 1 117336 164 1
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors
Tcp: 1 200 120000 -1 12562 306 1061 172 137 1264809 1246746 296 84 12940 82
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
Udp: 138987 164 0 139190 0 0 0 0 0
UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
UdpLite: 0 0 0 0 0 0 0 0 0
```

该信息也可以通过命令`netstat -s`来获取。相比于`dropwatch`，通过`snmp`我们可以获取到一些丢包问题产生的原因，如校验和错误（`InCsumErrors`）、缓冲区满了（`RcvbufErrors`）等。但是`snmp`毕竟是整个系统中的统计信息，无法定位、监控特定的报文丢包的原因（毕竟一个系统中可能存在着大量的丢包事件）。通过给`snmp`增加`tracepoint`点，我们就可以通过一些手段（如eBPF）来进行`trace`，获取到被丢弃的报文的内容和原因。笔者将该方案提交到了`kernel`社区，网络模块的`maintainer`之一的`David Ahern`给出的建议是，相比于增加`snmp`的`tracepoint`点，新增一个接口`kfree_skb_reason()`并扩展当前的`kfree_skb`事件可能的更好的选择，因为这样就可以无缝对接到`drop monitor`模块，一些第三方工具（如`dropwatch`、`wireshark`）也可以受益于该功能。虽然这将产生大量的修改（内核中使用`kfree_skb`的地方约有2000+处），经过深思熟虑，笔者还是采用了该方案，毕竟这种方案在扩展新的丢包原因方面有着更加灵活的优势。相关的讨论可见[net: snmp: tracepoint support for snmp](https://lore.kernel.org/netdev/20211118124812.106538-1-imagedong@tencent.com/)

经过修改后，当前的`kfree_skb`事件已经变成了这样：

```shell
root@imagedong-LC1:/home/xm# cat /tracing/trace
# tracer: nop
#
# entries-in-buffer/entries-written: 26/26   #P:64
#
#                                _-----=> irqs-off/BH-disabled
#                               / _----=> need-resched
#                              | / _---=> hardirq/softirq
#                              || / _--=> preempt-depth
#                              ||| / _-=> migrate-disable
#                              |||| /     delay
#           TASK-PID     CPU#  |||||  TIMESTAMP  FUNCTION
#              | |         |   |||||     |         |
          <idle>-0       [013] .Ns2. 176394.894120: kfree_skb: skbaddr=00000000b09a26bc protocol=2048 location=00000000751c2330 reason: TCP_INVALID_SEQUENCE
          <idle>-0       [028] ..s2. 176398.260716: kfree_skb: skbaddr=00000000da3ef973 protocol=2048 location=00000000751c2330 reason: TCP_INVALID_SEQUENCE
```

在丢包事件中，用户已经可以清晰地看出报文丢包的原因。该功能发布于Kernel5.18版本中，经过笔者的不懈努力，目前常用的网络协议，如`IP`、`TCP`、`UDP`、`ICMP`等已经完成了接口的替换，抽象出来的各个协议层的丢包原因也将近70个。

虽然`dropwatch`目前也已经支持了丢包原因，但是该工具目前还不支持报文过滤的功能，也不能直接显示报文内容，使用起来多有不便。综合考虑，笔者决定基于eBPF自己写一个轻量级的用于丢包监控的工具，并命名为`droptrace`，作为`nettrace`工具下的一个子工具（不排除后期将功能合并到nettrace中的可能）。

## 二、使用方法

`droptrace`是采用C语言编写的基于`eBPF/libbpf`的命令行工具，在构建时采用的静态编译。因此运行时不依赖于第三方库，具有轻量化的特点，在嵌入式等场景下也可以适用。

### 2.1 构建

可以直接从`github`中下载编译好的二进制程序`droptrace`或者`nettrace`的rpm包，也可以自行进行编译构建：

```shell
git clone https://github.com/OpenCloudOS/nettrace.git
cd nettrace/droptrace
make all
```

由于构建过程中需要动态生成`vmlinux.h`头文件，因此需要当前构建环境开启了`CONFIG_DEBUG_INFO_BTF`配置。如果没有配置，则需要通过VMLINUX手动指定内核的`vmlinux`文件路径，如：

```
make VMLINUX=/home/test/linux/vmlinux all
```

### 2.2 功能介绍

在使用和显示方面，该工具与tcpdump类似，可以通过指定过滤条件（如IP地址、端口、协议等）来筛选被丢弃的报文，基本用法如下：

```shell
$ sudo droptrace --saddr 127.0.0.1
[2553.203430] 127.0.0.1:51136 -> 127.0.0.1:56100 TCP seq:2144353195, ack:461890105, flags:A reason:TCP_INVALID_SEQUENCE tcp_validate_incoming+0x132
[2573.683437] 127.0.0.1:56101 -> 127.0.0.1:52010 TCP seq:2111110047, ack:4270738862, flags:A reason:TCP_INVALID_SEQUENCE tcp_validate_incoming+0x132
[2573.683455] 127.0.0.1:52010 -> 127.0.0.1:56101 TCP seq:4253961646, ack:2127887263, flags:A reason:TCP_INVALID_SEQUENCE tcp_validate_incoming+0x132
```

该命令用来监控系统中所有源地址为`127.0.0.1`的丢包报文。输出中的**reason**即为**丢包原因**，如果对该原因和解决办法不太理解，还可以使用命令`man dropreason`命令来查看丢包原因用户手册中对其所做出的详细解释（该手册还是不断完善中）：

```shell
Constants
       SKB_NOT_DROPPED_YET
                   skb is not dropped yet (used for no-drop case)

       SKB_DROP_REASON_NOT_SPECIFIED
                   drop reason is not specified

       SKB_DROP_REASON_NO_SOCKET
                   socket not found

       SKB_DROP_REASON_PKT_TOO_SMALL
                   packet size is too small

       SKB_DROP_REASON_TCP_CSUM
                   TCP checksum error

       SKB_DROP_REASON_SOCKET_FILTER
                   dropped by socket filter

       SKB_DROP_REASON_UDP_CSUM
                   UDP checksum error

       SKB_DROP_REASON_NETFILTER_DROP
                   dropped by netfilter
       
       ......
```

输出信息中的最后一个字段为产生丢包的指令地址（内核函数），该信息和`dropwatch`中所提供的一致。

使用`-h`可以查看工具支持的所有功能：

```shell
$ droptrace -h
droptrace: a tool to monitor the packet dropped by kernel

Usage:
    -s, --saddr      filter source ip address
    -d, --daddr      filter dest ip address
    --addr           filter source or dest ip address
    -S, --sport      filter source TCP/UDP port
    -D, --dport      filter dest TCP/UDP port
    -P, --port       filter source or dest TCP/UDP port
    -p, --proto      filter L3/L4 protocol, such as 'tcp', 'arp'
    -r, --reason     filter drop reason

    --raw-sym        show kernel symbol address (default false)
    --stat           show drop statistics
    --stat-stop      stop drop statistics and remove the launched eBPF program
    -l, --limit      set the max output pcaket per second, defaultunlimited
    --limit-budget   set the budget depth of the token used to limitoutput rate
    -h, --help       show help information
```

前面的几个参数是用来进行报文过滤的，比较好理解，这里着重介绍一下剩余的几个参数的功能。

- `raw-sym`：显示原始丢包指令地址。跟踪数据中的`tcp_validate_incoming+0x132`是工具将指令地址解析成的内核函数信息，如果想看到未经解析的地址，可以加上该参数。这在用户想要通过addr2line命令来定位到具体的代码行的时候比较有用。
- `stat`：丢包统计模式。该模式下，会挂载eBPF程序到系统中来统计各个原因下所产生的的丢包数量（该模式暂不支持指定过滤条件）。
- `stat-stop`：停止丢包统计。使用该参数，会将原先使用`stat`加载到内核中的eBPF卸载掉，停止丢包统计。
- `limit`：限制输出频率。如果系统中存在大量的丢包，`droptrace`的输出就会很多。该参数可以限制每秒所跟踪的报文的数量，其采用令牌桶的方式来实现。
- `limit-budget`：令牌桶的深度。

丢包统计模式下的输出信息如下所示：

```shell
$ sudo droptrace --stat
packet statistics:
  NOT_SPECIFIED: 0
  NO_SOCKET: 0
  PKT_TOO_SMALL: 0
  TCP_CSUM: 0
  SOCKET_FILTER: 49
  UDP_CSUM: 13
  NETFILTER_DROP: 0
  OTHERHOST: 0
  IP_CSUM: 0
  IP_INHDR: 0
  IP_RPFILTER: 0
  UNICAST_IN_L2_MULTICAST: 0
  ......
```

## 三、注意事项

目前所有的丢包原因都保存在内核中的枚举类型`enum skb_drop_reason`中。虽然笔者在开发过程中尽量将新增的丢包原因添加到到枚举的尾部来保持兼容，但是社区上的有些开发者认为丢包原因是通过字符串的方式由`ftrace`传递给用户的，所以将新增的原因加到枚举中间位置也是被接受的。为了保持最好的兼容性，不建议直接下载`release`中的二进制程序`droptrace`来使用，最好的方式是在目标机器上编译后使用。