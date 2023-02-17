# nettrace - 网络诊断工具

## 一、工具简介

### 1.1 背景

在一些场景下（特别是云原生场景），Linux系统中的网络部署变得越来越复杂。一个TCP连接，从客户端到服务端，中间可能要经过复杂的`NAT`、`GRE`、`IPVS`等过程，网络报文在节点（主机）上的处理路径也变得越来越长。在发生网络故障（比如网络丢包）时，如何快速、有效地定位出网络问题成为了一个难题。目前常规的网络故障定位手段，如`tcpdump`、`dropwatch`、`ftrace`、`kprobe`等存在一定的短板：

- `tcpdump`：只能在链路层抓包，无法定位内核协议栈中的问题，比如常规的内核丢包问题
- `ftrace`：只能跟踪内核函数，无法进行报文过滤，且入手较难，需要对内核协议栈有一定了解
- `kprobe`：临时编写内核模块，效率和安全性低
- `BCC`：功能单一，临时编写`BCC`程序跟踪效率低，需要对内核有一定了解，入手难
- `dropwatch`：功能单一，只能查看网络丢包问题，且无法得到丢包原因和解决方案

在此背景下，笔者结合多年的Kernel网络协议栈故障定位经验，基于eBPF开发了Linux环境下网络故障定位工具集——`nettrace`。

### 1.2 功能介绍

`nettrace`是一款基于eBPF的集网络报文跟踪（故障定位）、网络故障诊断、网络异常监控于一体的网络工具集，旨在能够提供一种更加高效、易用的方法来解决复杂场景下的网络问题。目前，其实现的功能包括：

- 网络报文跟踪：跟踪网络报文从进入到内核协议栈到释放/丢弃的过程中在内核中所走过的路径，实现报文整个生命周期的监控，并采集生命周期各个阶段的事件、信息。通过观察报文在内核中的路径，对于有一定内核协议栈经验的人来说可以快速、有效地发现网络问题。
- 网络故障诊断：将以往的经验集成到工具的知识库，通过知识匹配的方式来主动诊断当前网络故障，给出诊断结果以及修复建议。该功能入手简单、易用性强，无需过多的网络经验即可进行网络问题定位。
- 网络异常监控：常态化地部署到生产环境中，主动地发现、上报环境上的网络异常。
- `droptrace`：用于跟踪、监控系统中的丢包事件的工具，点击[这里](docs/droptrace.md)查看详情介绍。该功能已被遗弃，可以使用`nettrace --drop`实现相同的功能。

## 二、安装方法

nettrace是采用C语言编写的基于eBPF（libbpf）的命令行工具，在使用和安装时可以用编译好的RPM包和二进制程序。**注意**：本工具目前仅在`4.14`及以上的内核版本上进行过兼容性测试，因此请确保当前的系统所使用的的内核版本在`4.14`以上。

### 2.1 RPM/DEB安装

对于支持BTF特性（内核版本 >= 5.3，并且配置了`CONFIG_DEBUG_INFO_BTF=y`内核配置项）的内核，可以直接下载[releases](https://github.com/OpenCloudOS/nettrace/releases)中编译好的`nettrace-xxx-1.btf.x86_64.rpm`、`nettrace-xxx-1.btf.x86_64.deb`安装包进行安装使用；对于不支持BTF的低版本的内核，需要在对应的系统上手动编译后才能使用。对于OpenCloudOS/TencentOS系统，可以直接使用yum命令来进行在线安装：

```shell
sudo yum install nettrace
```

也可以直接从[releases](https://github.com/OpenCloudOS/nettrace/releases)中下载对应的RPM/DEB安装包，手动进行安装。

### 2.2 二进制下载

直接从[releases](https://github.com/OpenCloudOS/nettrace/releases)下载编译好的二进制包也是可以的，[releases](https://github.com/OpenCloudOS/nettrace/releases)中的`tar.bz2`格式的压缩包即为二进制程序。由于里面的工具采用的都是静态编译的方式，因此在内核版本支持的情况下，都是可以直接下载解压后运行的。**再次提醒**：对于不支持BTF的内核版本，需要手动编译才能使用。

### 2.3 手动编译

下面来介绍下如何在Centos、ubuntu等环境上进行nettrace工具的手动编译和安装。本工具目前在4.14/4.15/5.4/5.10/5.18等版本的内核上均进行过适配和测试，更低版本的内核暂未进行适配。由于本工具对于libbpf的版本要求比较高，因此建议使用**基于docker**的方式来进行编译。

#### 2.3.1 依赖安装

本工具在编译的时候依赖于`libelf`、`libbpf`和`bpftool`组件，`clang`和`gcc`编译工具。对于不支持BTF的内核，还需要安装`kernel-headers`头文件，可以通过查看目录`/lib/modules/$(uname -a)/build`是否存在来判断`headers`是否已经被安装了。

**注意事项**：
1. 请尽量使用较高版本的libbpf（v0.2以上版本）。如果当前发行版的libbpf库版本达不到要求，可以手动进行libbpf的编译安装：

    ```shell
    wget https://github.com/libbpf/libbpf/archive/refs/tags/v1.1.0.tar.gz
    tar -xf v1.1.0.tar.gz
    cd libbpf-1.1/src
    make install
    ```

2. clang版本要在10+

##### ubuntu

对于ubuntu系统，使用以下命令安装依赖：

```shell
sudo apt install libelf-dev libbpf-dev linux-headers-`uname -r` clang llvm gcc linux-tools-`uname -r` linux-tools-generic -y
```

##### opencloudos/tencentos/centos

对于opencloudos/tencentos/centos用户，使用以下命令来安装依赖：

```shell
sudo yum install elfutils-devel elfutils-devel-static libbpf-devel libbpf-static kernel-headers kernel-devel clang llvm bpftool -y
```

#### 2.3.2 编译

直接下载nettrace的源码即可进行编译安装：

```shell
git clone https://github.com/OpenCloudOS/nettrace.git
cd nettrace
make all
```

**注意**：对于不支持BTF的内核（内核版本低于5.3），在编译的时候需要加参数`COMPAT=1`，如下所示：

```shell
make COMPAT=1 all
```

启用该参数，eBPF程序会以BPF_PROBE_READ的方式来读取数据；否则，eBPF程序会以BPF_CORE_READ的方式来读取。可以使用KERNEL来手动指定要使用的内核源码（内核头文件）：

```shell
make KERNEL=/home/ubuntu/kernel COMPAT=1 all
```

对于发行版版本较低，难以安装高版本clang的情况下，可以基于docker来进行代码的编译，具体可参考[2.4](#2.4-基于docker编译)章节来进行安装。

同时，对于`ubuntu 16.04/ubuntu 18.04`系统，其内核似乎存在BUG，即其使用的内核版本实际为4.15.18，uname看到的却是4.15.0。这导致了加载eBPF程序的时候内核版本不一致，无法加载。因此对于这种情况，可以使用KERN_VER参数来手动指定内核版本（计算方式为：`(4<<16) + (15<<8) + 18`）：

```shell
make KERN_VER=266002 COMPAT=1 all
```

#### 2.3.3 打包

使用命令`make rpm`可制作rpm包；使用命令`make pack`可制作二进制包（二进制程序打包到压缩包中，默认存放路径为output文件夹）。

### 2.4 基于docker编译

对于**支持BTF**的内核，无需安装任何依赖，可以直接使用以下命令来进行nettrace的编译，其中：`<nettrace path>`要替换成nettrace代码的绝对路径：

```shell
docker run -it --rm --network=host --privileged -v <nettrace path>:/root/nettrace -v /lib/modules/:/lib/modules/ -v /usr/src/:/usr/src/ imagedong/nettrace-build make -C /root/nettrace/ all
```

对于**不支持BTF**的系统，这需要先安装`kernel-headers`软件包，如上面的手动编译里面所说的。ubuntu系统使用命令`apt install linux-headers-$(uname -r) -y`进行安装；centos使用命令`yum install kernel-headers kernel-devel -y`进行安装。然后使用下面的命令进行编译：

```shell
docker run -it --rm --network=host --privileged -v <nettrace path>:/root/nettrace -v /lib/modules/:/lib/modules/ -v /usr/src/:/usr/src/ imagedong/nettrace-build make -C /root/nettrace/ COMPAT=1 all
```

**注意：** docker镜像可能会更新，为了使用最新的镜像，建议先试用命令`docker pull imagedong/nettrace-build`来获取最新的容器镜像。

## 三、使用方法

nettrace是用来跟踪内核报文和诊断网络故障的，在进行报文跟踪时可以使用一定的过滤条件来跟踪特定的报文。其基本命令行参数为：

```shell
$ nettrace -h
nettrace: a tool to trace skb in kernel and diagnose network problem

Usage:
    -s, --saddr      filter source ip/ipv6 address
    -d, --daddr      filter dest ip/ipv6 address
    --addr           filter source or dest ip/ipv6 address
    -S, --sport      filter source TCP/UDP port
    -D, --dport      filter dest TCP/UDP port
    -P, --port       filter source or dest TCP/UDP port
    -p, --proto      filter L3/L4 protocol, such as 'tcp', 'arp'
    --pid            filter by current process id(pid)
    -t, --trace      enable trace group or trace
    --ret            show function return value
    --detail         show extern packet info, such as pid, ifname, etc
    --date           print timestamp in date-time format
    --basic          use 'basic' trace mode, don't trace skb's life
    --diag           enable 'diagnose' mode
    --diag-quiet     only print abnormal packet
    --diag-keep      don't quit when abnormal packet found
    --hooks          print netfilter hooks if dropping by netfilter
    --drop           skb drop monitor mode, for replace of 'droptrace'
    --drop-stack     print the kernel function call stack of kfree_skb

    -v               show log information
    --debug          show debug information
    --bpf-debug      show bpf debug information
    -h, --help       show help information
```

其中，参数`s/d/addr/S/D/port/p/pid`用于进行报文的过滤，可以通过IP地址、端口、协议等属性进行过滤。其中，通过IPv6地址进行过滤目前也已经实现了支持。其他参数的用途包括：

- `t/trace`：要启用的跟踪模块，默认启用所有
- `ret`：跟踪和显示内核函数的返回值
- `detail`：显示跟踪详细信息，包括当前的进程、网口和CPU等信息
- `date`：以时间格式打印（以2022-10-24 xx:xx:xx.xxxxxx格式打印），而不是时间戳
- `basic`：启用`basic`跟踪模式。默认情况下，启用的是生命周期跟踪模式。启用该模式后，会直接打印出报文所经过的内核函数/tracepoint。
- `diag`：启用诊断模式
- `diag-quiet`：只显示出现存在问题的报文，不显示正常的报文
- `diag-keep`：持续跟踪。`diag`模式下，默认在跟踪到异常报文后会停止跟踪，使用该参数后，会持续跟踪下去。
- `hooks`：结合netfilter做的适配，详见下文
- `drop`：进行系统丢包监控，取代原先的`droptrace`
- `drop-stack`: 打印kfree_skb内核函数的调用堆栈

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

使用方式与上面的一致，加个`diag`参数即可使用诊断模式。上文的生命周期模式对于使用者的要求比较高，需要了解内核协议栈各个函数的用法、返回值的意义等，易用性较差。诊断模式是在生命周期模式的基础上，提供了更加丰富的信息，使得没有网络开发经验的人也可进行复杂网络问题的定位和分析。

#### 3.2.1 基本用法

下面是使用诊断模式进行报文跟踪的用法，可以看出来相比于普通模式，诊断模式提供了更多的可供参考的信息，包括当前报文经过了iptables的哪些表和哪些链、报文发生了NAT、报文被克隆了等。诊断模式设置了三种提示级别：

- `INFO`：正常的信息提示
- `WARN`：警告信息，该报文可能存在一定的问题，需要关注
- `ERROR`：异常信息，报文发生了问题（比如被丢弃）。

```shell
./nettrace -p icmp --diag --saddr 192.168.122.8
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

如果当前报文存在`ERROR`，那么工具会给出一定的诊断修复建议，并终止当前诊断操作。通过添加`diag-keep`可以在发生`ERROR`事件时不退出，继续进行跟踪分析。下面是发生异常时的日志：

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

从这里的日志可以看出，在报文经过iptables的filter表的forward链的时候，发生了丢包。在诊断结果里，会列出所有的异常事件，一个报文跟踪可能会命中多条诊断结果。这里的诊断建议是让用户检查iptables中的规则是否存在问题。

其中，`kfree_skb`这个跟踪点是对`drop reason`内核特性（详见[droptrace](docs/droptrace.md)中的介绍）做了适配的，可以理解为将droptrace的功能集成到了这里的诊断结果中，这里可以看出其给出的对包原因是`NETFILTER_DROP`。

#### 3.2.2 netfilter支持

网络防火墙是网络故障、网络不同发生的重灾区，因此`netfilter`工具对`netfilter`提供了完美适配，包括老版本的`iptables-legacy`和新版本的`iptables-nft`。诊断模式下，`nettrace`能够跟踪报文所经过的`iptables`表和`iptables`链，并在发生由于iptables导致的丢包时给出一定的提示，上面的示例充分展现出了这部分。出了对iptables的支持，`nettrace`对整个netfilter大模块也提供了支持，能够显示在经过每个HOOK点时对应的协议族和链的名称。除此之外，为了应对一些注册到netfilter中的第三方内核模块导致的丢包问题，nettrace还可以通过添加参数`hooks`来打印出当前`HOOK`上所有的的钩子函数，从而深入分析问题：

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

可以看出，上面`following hook functions are blamed`中列出了导致当前`netfilter`丢包的所有的钩子函数，这里只有`iptables`一个钩子函数。

#### 3.2.3 其他场景

由于对`drop reason`内核特性进行了适配，因此对于支持`drop reason`的系统，基于`drop reason`本工具可以诊断70+种丢包问题。`nettrace`通过将网络诊断经验翻译成规则存储到规则库的方式来进行诊断分析，通过扩充规则配置文件的方式能够不断增强其诊断功能。目前，本工具已经集成了20+典型网络故障诊断功能，并且在实践中不断完善知识库（规则库）。

端口未监听导致的丢包：

```shell
./nettrace --diag --diag-quiet
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
./nettrace -p icmp --diag --diag-quiet 
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

## 3.3 丢包监控

使用命令`nettrace --drop`可以对系统中的丢包事件进行监控，对于支持内核特性`skb drop reason`的内核，这里还会打印出丢包原因。可以通过查看`/tracing/events/skb/kfree_skb/format`来判断当前系统是否支持该特性：

```shell
cat /tracing/events/skb/kfree_skb/format 
name: kfree_skb
ID: 1524
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:void * skbaddr;   offset:8;       size:8; signed:0;
        field:void * location;  offset:16;      size:8; signed:0;
        field:unsigned short protocol;  offset:24;      size:2; signed:0;
        field:enum skb_drop_reason reason;      offset:28;      size:4; signed:0;

print fmt: "skbaddr=%p protocol=%u location=%p reason: %s", REC->skbaddr, REC->protocol, REC->location, __print_symbolic(REC->reason, { 1, "NOT_SPECIFIED" }, { 2, "NO_SOCKET" }, { 3, "PKT_TOO_SMALL" }, { 4, "TCP_CSUM" }, { 5, "SOCKET_FILTER" }, { 6, "UDP_CSUM" }, { 7, "NETFILTER_DROP" }, { 8, "OTHERHOST" }, { 9, "IP_CSUM" }, { 10, "IP_INHDR" }, { 11, "IP_RPFILTER" }, { 12, "UNICAST_IN_L2_MULTICAST" }, { 13, "XFRM_POLICY" }, { 14, "IP_NOPROTO" }, { 15, "SOCKET_RCVBUFF" }, { 16, "PROTO_MEM" }, { 17, "TCP_MD5NOTFOUND" }, { 18, "TCP_MD5UNEXPECTED" }, { 19, "TCP_MD5FAILURE" }, { 20, "SOCKET_BACKLOG" }, { 21, "TCP_FLAGS" }, { 22, "TCP_ZEROWINDOW" }, { 23, "TCP_OLD_DATA" }, { 24, "TCP_OVERWINDOW" }, { 25, "TCP_OFOMERGE" }, { 26, "TCP_RFC7323_PAWS" }, { 27, "TCP_INVALID_SEQUENCE" }, { 28, "TCP_RESET" }, { 29, "TCP_INVALID_SYN" }, { 30, "TCP_CLOSE" }, { 31, "TCP_FASTOPEN" }, { 32, "TCP_OLD_ACK" }, { 33, "TCP_TOO_OLD_ACK" }, { 34, "TCP_ACK_UNSENT_DATA" }, { 35, "TCP_OFO_QUEUE_PRUNE" }, { 36, "TCP_OFO_DROP" }, { 37, "IP_OUTNOROUTES" }, { 38, "BPF_CGROUP_EGRESS" }, { 39, "IPV6DISABLED" }, { 40, "NEIGH_CREATEFAIL" }, { 41, "NEIGH_FAILED" }, { 42, "NEIGH_QUEUEFULL" }, { 43, "NEIGH_DEAD" }, { 44, "TC_EGRESS" }, { 45, "QDISC_DROP" }, { 46, "CPU_BACKLOG" }, { 47, "XDP" }, { 48, "TC_INGRESS" }, { 49, "UNHANDLED_PROTO" }, { 50, "SKB_CSUM" }, { 51, "SKB_GSO_SEG" }, { 52, "SKB_UCOPY_FAULT" }, { 53, "DEV_HDR" }, { 54, "DEV_READY" }, { 55, "FULL_RING" }, { 56, "NOMEM" }, { 57, "HDR_TRUNC" }, { 58, "TAP_FILTER" }, { 59, "TAP_TXFILTER" }, { 60, "ICMP_CSUM" }, { 61, "INVALID_PROTO" }, { 62, "IP_INADDRERRORS" }, { 63, "IP_INNOROUTES" }, { 64, "PKT_TOO_BIG" }, { 65, "MAX" })
```

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

同样可以使用`man dropreason`命令来查看对应的丢包原因的详细解释。对于不支持`skb drop reason`特性的内核，该模式下将不会打印丢包原因字段，效果如下所示：

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

