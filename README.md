# nettrace - 网络诊断工具

## 一、工具简介

### 1.1 背景

在一些场景下（特别是云原生场景），Linux系统中的网络部署变得越来越复杂。一个TCP连接，从客户端到服务端，中间可能要经过复杂的`NAT`、`GRE`、IPVS`等`过程，网络报文在节点（主机）上的处理路径也变得越来越长。在发生网络故障（比如网络丢包）时，如何快速、有效地定位出网络问题成为了一个难题。目前常规的网络故障定位手段，如`tcpdump`、`dropwatch`、`ftrace`、`kprobe`等存在一定的短板：

- `tcpdump`：只能在链路层抓包，无法定位内核协议栈中的问题，比如常规的内核丢包问题
- `ftrace`：只能跟踪内核函数，无法进行报文过滤，且入手较难，需要对内核协议栈有一定了解
- `kprobe`：临时编写内核模块，效率和安全性低
- `BCC`：功能单一，临时编写`BCC`程序跟踪效率低，需要对内核有一定了解，入手难
- `dropwatch`：功能单一，只能查看网络丢包问题，且无法得到丢包原因和解决方案

在此背景下，笔者结合多年的Kernel网络协议栈故障定位经验，基于eBPF开发了Linux环境下网络故障定位工具集——`nettrace`。

### 1.2 功能介绍

`nettrace`是一款基于eBPF的集网络报文跟踪（故障定位）、网络故障诊断、网络异常监控于一体的网络工具集，旨在能够提供一种更加高效、易用的方法来解决复杂场景下的网络问题。目前，其实现的功能包括：

- 报文生命周期跟踪：跟踪网络报文从进入到内核协议栈到释放/丢弃的过程中在内核中所走过的路径，实现报文整个生命周期的监控，并采集生命周期各个阶段的事件、信息。通过观察报文在内核中的路径，对于有一定内核协议栈经验的人来说可以快速、有效地发现网络问题。
- 网络故障诊断：将以往的经验集成到工具的知识库，通过知识匹配的方式来主动诊断当前网络故障，给出诊断结果以及修复建议。该功能入手简单、易用性强，无需过多的网络经验即可进行网络问题定位。
- 网络异常监控：常态化地部署到生产环境中，主动地发现、上报环境上的网络异常。
- `droptrace`：用于跟踪、监控系统中的丢包事件的工具，点击[这里](droptrace/README.md)查看详情介绍。该工具计划后面合入到`nettrace`功能中。

## 二、安装方法

nettrace是采用C语言编写的基于eBPF（libbpf）的命令行工具，在使用和安装时可以用编译好的RPM包和二进制程序。需要注意的是，github上发布的RPM和二进制程序都是基于TencentOS（5.4.119内核版本）编译的，对于不支持CORE的其他版本的内核，最好下载源码编译后使用，以防止数据结构不兼容的问题。

### 2.1 RPM安装

对于TencentOS系统，可以直接使用yum命令来进行在线安装：

```shell
sudo yum install nettrace
```

也可以直接从[releases](https://github.com/OpenCloudOS/nettrace/releases)中下载对应的RPM安装包，手动进行安装。

### 2.2 二进制下载

直接从[releases](https://github.com/OpenCloudOS/nettrace/releases)下载编译好的二进制包也是可以的，[releases](https://github.com/OpenCloudOS/nettrace/releases)中的`tar.bz2`格式的压缩包即为二进制程序。由于里面的工具采用的都是静态编译的方式，因此在内核版本支持的情况下，都是可以直接下载解压后运行的。再次提醒：对于不支持`CO-RE`模式的非`TencentOS`的内核版本，最好在对应的环境上编译后使用。

### 2.3 手动编译

下面来介绍下如何在Centos、ubuntu等环境上进行nettrace工具的手动编译和安装。本工具目前仅在5.4+的内核上进行过适配和测试，更低版本的内核暂未进行适配，后面会进行完善。

#### 2.3.1 依赖安装

本工具在编译的时候依赖于`libelf`、`libbpf`和`bpftool`组件。其中，bpftool二进制程序已经直接预编译好放到源码包的script目录中，因此无需安装。对于支持BTF（即存在文件`/sys/kernel/btf/vmlinux`），可以不用安装headers头文件。

对于ubuntu系统，使用以下命令安装依赖：

```shell
sudo apt install libelf-dev libbpf-dev linux-headers-amd64
```

对于centos用于，使用以下命令来安装依赖：

```shell
sudo yum install elfutils-devel elfutils-devel-static libbpf-devel libbpf-static kernel-headers
```

在编译过程中，如果因为libbpf导致了编译失败，或者当前发行版没有libbpf可以安装，那么请点击[这里](https://github.com/libbpf/libbpf/releases)下载安装较新版本的libbpf：

```shell
wget https://github.com/libbpf/libbpf/archive/refs/tags/v0.2.tar.gz
tar -xf v0.2.tar.gz
cd libbpf-0.2/src
make install
```

#### 2.3.2 编译

直接下载nettrace的源码即可进行编译安装：

```shell
git clone https://github.com/OpenCloudOS/nettrace.git
cd nettrace
make all
```

也可以单独编译其中的某个子工具，例如只编译nettrace命令：

```shell
make -C src all
```

可以使用KERNEL来手动指定要使用的内核源码（内核头文件）：

```shell
make KERNEL=/home/ubuntu/kernel all
```

也可以使用VMLINUX来指定BTF的源文件（即不使用默认的`/sys/kernel/btf/vmlinux`路径）：

```shell
make VMLINUX=/home/ubuntu/kernel/vmlinux all
```

## 三、使用方法

`droptrace`主要用来进行系统丢包事件的监控，点击[这里](droptrace/README.md)可查看droptrace的用户文档，这里不再赘述，重点介绍nettrace的相关功能。nettrace是用来跟踪内核报文和诊断网络故障的，在进行报文跟踪时可以使用一定的过滤条件来跟踪特定的报文。其基本命令行参数为：

```shell
$ nettrace -h
nettrace: a tool to trace skb in kernel and diagnose network problem

Usage:
    -s, --saddr      filter source ip address
    -d, --daddr      filter dest ip address
    --addr           filter source or dest ip address
    -S, --sport      filter source TCP/UDP port
    -D, --dport      filter dest TCP/UDP port
    -P, --port       filter source or dest TCP/UDP port
    -p, --proto      filter L3/L4 protocol, such as 'tcp', 'arp'
    -t, --trace      enable trace group or trace
    --ret            show function return value
    --detail         show extern packet info, such as pid, ifname, etc
    --basic          use 'basic' trace mode, don't trace skb's life
    --intel          enable 'intel' mode
    --intel-quiet    only print abnormal packet
    --intel-keep     don't quit when abnormal packet found
    --hooks          print netfilter hooks if dropping by netfilter

    -v               show log information
    --debug          show debug information
    -h, --help       show help information
```

其中，参数`s/d/addr/S/D/port/p`用于进行报文的过滤，可以通过IP地址、端口、协议等属性进行过滤。其他参数的用途包括：

- `t/trace`：要启用的跟踪模块，默认启用所有
- `ret`：跟踪和显示内核函数的返回值
- `detail`：显示跟踪详细信息，包括当前的进程、网口和CPU等信息
- `basic`：启用`basic`跟踪模式。默认情况下，启用的是生命周期跟踪模式。启用该模式后，会直接打印出报文所经过的内核函数/tracepoint。
- `intel`：启用诊断模式
- `intel-quiet`：只显示出现存在问题的报文，不显示正常的报文
- `intel-keep`：持续跟踪。`intel`模式是下，默认在跟踪到异常报文后会停止跟踪，使用该参数后，会持续跟踪下去。
- `hooks`：结合netfilter做的适配，详见下文

下面我们首先来看一下默认模式下的工具使用方法。

### 3.1 生命周期

默认情况下，`nettrace`会跟踪报文从进入到内核协议栈到离开（销毁）的过程。对于有一定内核网络经验的人来说，可以通过报文的内核路径来快速推断出当前的网络问题，达到快速定位的目的。

#### 3.1.1 跟踪ping报文

```shell
sudo ./nettrace -p icmp
begin trace...
***************** ffff889be8fbd500,ffff889be8fbcd00 ***************
[1272349.614564] [dev_gro_receive     ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220
[1272349.614579] [__netif_receive_skb_core] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220
[1272349.614585] [ip_rcv              ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220
[1272349.614592] [ip_rcv_core         ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220
[1272349.614599] [skb_clone           ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220
[1272349.614616] [nf_hook_slow        ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220
[1272349.614629] [nft_do_chain        ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220
[1272349.614635] [ip_rcv_finish       ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220
[1272349.614643] [ip_route_input_slow ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220
[1272349.614647] [fib_validate_source ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220
[1272349.614652] [ip_local_deliver    ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220
[1272349.614658] [nf_hook_slow        ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220
[1272349.614663] [ip_local_deliver_finish] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220
[1272349.614666] [icmp_rcv            ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220
[1272349.614671] [icmp_echo           ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220
[1272349.614675] [icmp_reply          ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220
[1272349.614715] [consume_skb         ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220
[1272349.614722] [packet_rcv          ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220
[1272349.614725] [consume_skb         ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 48220

***************** ffff889be8fbde00 ***************
[1272349.614681] [nf_hook_slow        ] ICMP: 172.27.0.6 -> 169.254.128.15 ping reply, seq: 48220
[1272349.614688] [ip_output           ] ICMP: 172.27.0.6 -> 169.254.128.15 ping reply, seq: 48220
[1272349.614690] [nf_hook_slow        ] ICMP: 172.27.0.6 -> 169.254.128.15 ping reply, seq: 48220
[1272349.614693] [ip_finish_output    ] ICMP: 172.27.0.6 -> 169.254.128.15 ping reply, seq: 48220
[1272349.614697] [ip_finish_output2   ] ICMP: 172.27.0.6 -> 169.254.128.15 ping reply, seq: 48220
[1272349.614705] [__dev_queue_xmit    ] ICMP: 172.27.0.6 -> 169.254.128.15 ping reply, seq: 48220
[1272349.614709] [dev_hard_start_xmit ] ICMP: 172.27.0.6 -> 169.254.128.15 ping reply, seq: 48220
[1272351.286866] [consume_skb         ] ICMP: 172.27.0.6 -> 169.254.128.15 ping reply, seq: 48220
```

上面的*中间的表示当前所跟踪的skb的地址，由于当前的报文被克隆过，因此当前跟踪上下文存在两个报文。

#### 3.1.2 指定过滤条件

```shell
sudo ./nettrace -p icmp --saddr 169.254.128.15
begin trace...
***************** ffff889be8fbc700,ffff889be8fbdc00 ***************
[1273445.360831] [dev_gro_receive     ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
[1273445.360844] [__netif_receive_skb_core] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
[1273445.360847] [ip_rcv              ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
[1273445.360850] [ip_rcv_core         ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
[1273445.360854] [skb_clone           ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
[1273445.360861] [nf_hook_slow        ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
[1273445.360868] [nft_do_chain        ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
[1273445.360875] [ip_rcv_finish       ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
[1273445.360878] [ip_route_input_slow ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
[1273445.360882] [fib_validate_source ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
[1273445.360887] [ip_local_deliver    ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
[1273445.360890] [nf_hook_slow        ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
[1273445.360895] [ip_local_deliver_finish] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
[1273445.360899] [icmp_rcv            ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
[1273445.360903] [icmp_echo           ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
[1273445.360908] [icmp_reply          ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
[1273445.360922] [consume_skb         ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
[1273445.360930] [packet_rcv          ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
[1273445.360933] [consume_skb         ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 54754
```

#### 3.1.3 显示详细信息

```shell
sudo ./nettrace -p icmp --saddr 169.254.128.15 --detail
begin trace...
***************** ffff889be8fbcd00,ffff889be8fbcc00 ***************
[1273732.110173] [ffff889be8fbcd00][dev_gro_receive     ][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
[1273732.110185] [ffff889be8fbcd00][__netif_receive_skb_core][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
[1273732.110189] [ffff889be8fbcd00][ip_rcv              ][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
[1273732.110192] [ffff889be8fbcd00][ip_rcv_core         ][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
[1273732.110196] [ffff889be8fbcd00][skb_clone           ][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
[1273732.110204] [ffff889be8fbcc00][nf_hook_slow        ][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
[1273732.110211] [ffff889be8fbcc00][nft_do_chain        ][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
[1273732.110222] [ffff889be8fbcc00][ip_rcv_finish       ][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
[1273732.110229] [ffff889be8fbcc00][ip_route_input_slow ][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
[1273732.110234] [ffff889be8fbcc00][fib_validate_source ][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
[1273732.110240] [ffff889be8fbcc00][ip_local_deliver    ][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
[1273732.110243] [ffff889be8fbcc00][nf_hook_slow        ][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
[1273732.110252] [ffff889be8fbcc00][ip_local_deliver_finish][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
[1273732.110255] [ffff889be8fbcc00][icmp_rcv            ][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
[1273732.110260] [ffff889be8fbcc00][icmp_echo           ][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
[1273732.110267] [ffff889be8fbcc00][icmp_reply          ][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
[1273732.110283] [ffff889be8fbcc00][consume_skb         ][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
[1273732.110291] [ffff889be8fbcd00][packet_rcv          ][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
[1273732.110294] [ffff889be8fbcd00][consume_skb         ][cpu:40 ][ens5 ][pid:0      ][swapper/40  ] ICMP: 169.254.128.15 -> 172.27.0.6 ping request, seq: 56464
```

可以看到，每个报文的地址、所在CPU、网口和进程信息都被打印了出来。

#### 3.1.4 NAT跟踪

在对报文进行跟踪时，一旦报文被跟踪起来（命中过滤条件），那么这个报文即使内容发生了变化也会持续被跟踪，知道报文被释放。下面是NAT场景下的跟踪，可以看到报文的源地址由`192.168.122.8`通过SNAT被修改成了`9.135.224.89`，但是报文依然被跟踪到了：

```shell
$ sudo ./nettrace -p icmp --addr 192.168.122.8
begin tracing......
<------------------- skb: ffff88818f02f900 ---------------------->
463697.331957: [__netif_receive_skb_core]: ICMP: 192.168.122.8 -> 10.123.119.98, ping request   , seq: 0
463697.331972: [nf_hook_slow            ]: ICMP: 192.168.122.8 -> 10.123.119.98, ping request   , seq: 0
463697.331985: [nf_hook_slow            ]: ICMP: 192.168.122.8 -> 10.123.119.98, ping request   , seq: 0
463697.331990: [__netif_receive_skb_core]: ICMP: 192.168.122.8 -> 10.123.119.98, ping request   , seq: 0
463697.331994: [ip_rcv                  ]: ICMP: 192.168.122.8 -> 10.123.119.98, ping request   , seq: 0
463697.331998: [ip_rcv_core             ]: ICMP: 192.168.122.8 -> 10.123.119.98, ping request   , seq: 0
463697.332001: [nf_hook_slow            ]: ICMP: 192.168.122.8 -> 10.123.119.98, ping request   , seq: 0
463697.332004: [ip_rcv_finish           ]: ICMP: 192.168.122.8 -> 10.123.119.98, ping request   , seq: 0
463697.332010: [ip_forward              ]: ICMP: 192.168.122.8 -> 10.123.119.98, ping request   , seq: 0
463697.332014: [nf_hook_slow            ]: ICMP: 192.168.122.8 -> 10.123.119.98, ping request   , seq: 0
463697.332024: [ip_output               ]: ICMP: 192.168.122.8 -> 10.123.119.98, ping request   , seq: 0
463697.332027: [nf_hook_slow            ]: ICMP: 192.168.122.8 -> 10.123.119.98, ping request   , seq: 0
463697.332037: [ip_finish_output        ]: ICMP: 9.135.224.89  -> 10.123.119.98, ping request   , seq: 0
463697.332039: [ip_finish_output2       ]: ICMP: 9.135.224.89  -> 10.123.119.98, ping request   , seq: 0
463697.332042: [dev_queue_xmit          ]: ICMP: 9.135.224.89  -> 10.123.119.98, ping request   , seq: 0
463697.332046: [dev_hard_start_xmit     ]: ICMP: 9.135.224.89  -> 10.123.119.98, ping request   , seq: 0
463697.332060: [consume_skb             ]: ICMP: 9.135.224.89  -> 10.123.119.98, ping request   , seq: 0
```

### 3.2 诊断模式

使用方式与上面的一致，加个`intel`参数即可使用诊断模式。上文的生命周期模式对于使用者的要求比较高，需要了解内核协议栈各个函数的用法、返回值的意义等，易用性较差。诊断模式是在生命周期模式的基础上，提供了更加丰富的信息，使得没有网络开发经验的人也可进行复杂网络问题的定位和分析。

#### 3.2.1 基本用法

下面是使用诊断模式进行报文跟踪的用法，可以看出来相比于普通模式，诊断模式提供了更多的可供参考的信息，包括当前报文经过了iptables的哪些表和哪些链、报文发生了NAT、报文被克隆了等。诊断模式设置了三种提示级别：

- `INFO`：正常的信息提示
- `WARN`：警告信息，该报文可能存在一定的问题，需要关注
- `ERROR`：异常信息，报文发生了问题（比如被丢弃）。

```shell
./nettrace -p icmp --intel --saddr 192.168.122.8
begin trace...
***************** ffff889fad356200 ***************
[3445.575957] [__netif_receive_skb_core] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[3445.575978] [nf_hook_slow        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *ipv4 in chain: PRE_ROUTING*
[3445.575990] [nft_do_chain        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *iptables table:nat, chain:PREROUT* *packet is accepted*
[3445.576005] [nf_hook_slow        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *bridge in chain: PRE_ROUTING*
[3445.576014] [__netif_receive_skb_core] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[3445.576024] [ip_rcv              ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[3445.576029] [ip_rcv_core         ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[3445.576040] [nf_hook_slow        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *ipv4 in chain: PRE_ROUTING*
[3445.576044] [ip_rcv_finish       ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[3445.576052] [ip_route_input_slow ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[3445.576061] [fib_validate_source ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[3445.576080] [ip_forward          ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[3445.576084] [nf_hook_slow        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *ipv4 in chain: FORWARD*
[3445.576087] [nft_do_chain        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *iptables table:filter, chain:FORWARD* *packet is accepted*
[3445.576107] [ip_output           ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[3445.576113] [nf_hook_slow        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *ipv4 in chain: POST_ROUTING*
[3445.576116] [nft_do_chain        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *iptables table:nat, chain:POSTROU* *packet is accepted*
[3445.576131] [nf_nat_manip_pkt    ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *NAT happens (packet address will change)*
[3445.576148] [ip_finish_output    ] ICMP: 192.168.255.10 -> 10.123.119.98 ping request, seq: 0
[3445.576152] [ip_finish_output2   ] ICMP: 192.168.255.10 -> 10.123.119.98 ping request, seq: 0
[3445.576158] [__dev_queue_xmit    ] ICMP: 192.168.255.10 -> 10.123.119.98 ping request, seq: 0
[3445.576165] [netdev_core_pick_tx ] ICMP: 192.168.255.10 -> 10.123.119.98 ping request, seq: 0
[3445.576177] [dev_hard_start_xmit ] ICMP: 192.168.255.10 -> 10.123.119.98 ping request, seq: 0
[3445.576215] [consume_skb         ] ICMP: 192.168.255.10 -> 10.123.119.98 ping request, seq: 0 *packet is freed (normally)*
---------------- ANALYSIS RESULT ---------------------
[1] WARNING happens in nf_nat_manip_pkt(netfilter):
        NAT happens (packet address will change)
```

如果当前报文存在`ERROR`，那么工具会给出一定的诊断修复建议，并终止当前诊断操作。通过添加`intel-keep`可以在发生`ERROR`事件时不退出，继续进行跟踪分析。下面是发生异常时的日志：

```shell
./nettrace -p icmp --intel --saddr 192.168.122.8
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

从这里的日志可以看出，在报文经过iptables的filter表的forward链的时候，发生了丢包。在诊断结果里，会列出所有的异常事件，一个报文跟踪可能会命中多条诊断结果。这里的诊断建议是让用户检查iptables中的规则是否存在问题。

其中，`kfree_skb`这个跟踪点是对`drop reason`内核特性（详见droptrace中的介绍）做了适配的，可以理解为将droptrace的功能集成到了这里的诊断结果中，这里可以看出其给出的对包原因是`NETFILTER_DROP`。

#### 3.2.2 netfilter支持

网络防火墙是网络故障、网络不同发生的重灾区，因此`netfilter`工具对`netfilter`提供了完美适配，包括老版本的`iptables-legacy`和新版本的`iptables-nft`。诊断模式下，`nettrace`能够跟踪报文所经过的`iptables`表和`iptables`链，并在发生由于iptables导致的丢包时给出一定的提示，上面的示例充分展现出了这部分。出了对iptables的支持，`nettrace`对整个netfilter大模块也提供了支持，能够显示在经过每个HOOK点时对应的协议族和链的名称。除此之外，为了应对一些注册到netfilter中的第三方内核模块导致的丢包问题，nettrace还可以通过添加参数`hooks`来打印出当前`HOOK`上所有的的钩子函数，从而深入分析问题：

```shell
./nettrace -p icmp --intel --saddr 192.168.122.8 --hooks
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

可以看出，上面`following hook functions are blamed`中列出了导致当前`netfilter`丢包的所有的钩子函数，这里只有`iptables`一个钩子函数。

#### 3.2.3 其他场景

由于对`drop reason`内核特性进行了适配，因此对于支持`drop reason`的系统，基于`drop reason`本工具可以诊断70+种丢包问题。`nettrace`通过将网络诊断经验翻译成规则存储到规则库的方式来进行诊断分析，通过扩充规则配置文件的方式能够不断增强其诊断功能。目前，本工具已经集成了20+典型网络故障诊断功能，并且在实践中不断完善知识库（规则库）。

端口未监听导致的丢包：

```shell
./nettrace --intel --intel-quiet
begin trace...
***************** ffff888f97730ee0 ***************
[365673.326016] [ip_output           ] TCP: 127.0.0.1:40392 -> 127.0.0.1:9999 seq:3067626996, ack:0, flags:S
[365673.326026] [ip_finish_output    ] TCP: 127.0.0.1:40392 -> 127.0.0.1:9999 seq:3067626996, ack:0, flags:S
[365673.326029] [ip_finish_output2   ] TCP: 127.0.0.1:40392 -> 127.0.0.1:9999 seq:3067626996, ack:0, flags:S
[365673.326032] [__dev_queue_xmit    ] TCP: 127.0.0.1:40392 -> 127.0.0.1:9999 seq:3067626996, ack:0, flags:S
[365673.326039] [dev_hard_start_xmit ] TCP: 127.0.0.1:40392 -> 127.0.0.1:9999 seq:3067626996, ack:0, flags:S
[365673.326042] [enqueue_to_backlog  ] TCP: 127.0.0.1:40392 -> 127.0.0.1:9999 seq:3067626996, ack:0, flags:S
[365673.326051] [__netif_receive_skb_core] TCP: 127.0.0.1:40392 -> 127.0.0.1:9999 seq:3067626996, ack:0, flags:S
[365673.326059] [ip_rcv              ] TCP: 127.0.0.1:40392 -> 127.0.0.1:9999 seq:3067626996, ack:0, flags:S
[365673.326061] [ip_rcv_core         ] TCP: 127.0.0.1:40392 -> 127.0.0.1:9999 seq:3067626996, ack:0, flags:S
[365673.326068] [ip_rcv_finish       ] TCP: 127.0.0.1:40392 -> 127.0.0.1:9999 seq:3067626996, ack:0, flags:S
[365673.326072] [ip_local_deliver    ] TCP: 127.0.0.1:40392 -> 127.0.0.1:9999 seq:3067626996, ack:0, flags:S
[365673.326075] [ip_local_deliver_finish] TCP: 127.0.0.1:40392 -> 127.0.0.1:9999 seq:3067626996, ack:0, flags:S
[365673.326078] [tcp_v4_rcv          ] TCP: 127.0.0.1:40392 -> 127.0.0.1:9999 seq:3067626996, ack:0, flags:S
[365673.326084] [__inet_lookup_listener] TCP: 127.0.0.1:40392 -> 127.0.0.1:9999 seq:3067626996, ack:0, flags:S *tcp port is not listened*
[365673.326090] [tcp_v4_send_reset   ] TCP: 127.0.0.1:40392 -> 127.0.0.1:9999 seq:3067626996, ack:0, flags:S
[365673.326125] [kfree_skb           ] TCP: 127.0.0.1:40392 -> 127.0.0.1:9999 seq:3067626996, ack:0, flags:S *packet is dropped by kernel*
---------------- ANALYSIS RESULT ---------------------
[1] WARNING happens in __inet_lookup_listener(tcp-in):
        tcp port is not listened
    fix advice:
        check your target tcp port

[2] ERROR happens in kfree_skb(life):
        packet is dropped by kernel
    location:
        tcp_v4_rcv+0x4a
```

XDP导致的丢包（XDP转发会给提示）：

```shell
./nettrace -p icmp --intel --intel-quiet 
begin trace...
***************** ffff889f015acc00 ***************
[18490.607809] [__netif_receive_skb_core] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[18490.607828] [nf_hook_slow        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *ipv4 in chain: PRE_ROUTING*
[18490.607840] [nft_do_chain        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *iptables table:nat, chain:PREROUT* *packet is accepted*
[18490.607855] [nf_hook_slow        ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *bridge in chain: PRE_ROUTING*
[18490.607874] [__netif_receive_skb_core] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0
[18490.607882] [netif_receive_generic_xdp] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *packet is dropped by XDP program*
[18490.607888] [kfree_skb           ] ICMP: 192.168.122.8 -> 10.123.119.98 ping request, seq: 0 *packet is dropped by kernel*
---------------- ANALYSIS RESULT ---------------------
[1] ERROR happens in netif_receive_generic_xdp(link-in):
        packet is dropped by XDP program
    fix advice:
        check your XDP eBPF program

[2] ERROR happens in kfree_skb(life):
        packet is dropped by kernel
    location:
        netif_receive_generic_xdp+0x259
    drop reason:
        NOT_SPECIFIED

analysis finished!
```
