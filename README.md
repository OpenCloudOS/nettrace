# nettrace

> 该分支为新特性分支（开发中），原始稳定版本在master分支哦

## 一、功能简介

nettrace是一款基于eBPF的Linux系统下的网络故障定位工具集合，目前其包含三个子工具：nettrace、droptrace和nodetrace，各个工具所适用的场景各不相同。

### 1.1 nettrace

基于BCC的网络报文跟踪工具，用于跟踪报文（skb）在内核中的生命周期，可以实现快速的网络故障定位。由于其会跟踪整个内核协议栈中的关键函数，因此会产生一定的性能开销，不适合在生产环境中常态化运行，比较适合主动进行疑难网络故障定位的场景。点击[nettrace](docs/nettrace.md)可查看详细介绍。

### 1.2 droptrace

基于eBPF的网络丢包监控工具，采用纯C语言开发，具有轻量化的特点，性能开销小，可用于生产环境上常态化部署使用。功能与dropwatch存在一定的相似，需要内核支持dropreason（丢包原因）特性，该特性在内核5.18版本中开始支持。点击[droptrace](docs/droptrace.md)可查看详细介绍。

### 1.3 nodetrace

节点报文跟踪，用于跟踪在集群环境中报文是在哪个节点中被丢弃的。在集群环境中，一个报文从发送端到接收端往往经过多重IPVS、NAT等过程，因此发生丢包时很难找到丢包所在的节点。该工具用于该场景下的报文跟踪，配合droptrace可获得事半功倍的效果哦。

## 二、使用方法

### 2.1 手动编译

克隆代码到本地后，执行编译命令即可：

```shell
git clone https://github.com/OpenCloudOS/nettrace
make all
```

也可进入到子工具目录，执行`make all`来单独编译。其中，droptrace的编译需要当前环境的内核支持dropreason特性。

### 2.2 rpm安装

下载[release](https://github.com/OpenCloudOS/nettrace/releases)中的rpm包，直接安装即可。

### 2.3 docker镜像

下载docker镜像来运行。对于要使用nettrace命令，单故障环境无法运行BCC的可选择这种方式，点击[nettrace](docs/nettrace.md)可查看详情。

### 2.4 可执行程序

由于droptrace和nodetrace都是静态编译的，因此也可以下载[release](https://github.com/OpenCloudOS/nettrace/releases)中的tar包，解压后即可使用其中的命令。其中的nettrace为经过整合后的单独的python程序。

## 三、版本计划：

### 3.1 nettrace

1. 基于原始libbpf重构nettrace代码。由于python性能比较低，对于报文量比较大的场景，报文处理速度跟不上，会产生事件丢失。同时，对BCC的依赖过于笨重，导致某些环境上难以运行。
2. 诊断功能。当前的nettrace对于使用者要求过高，需要对内核协议栈有一定的了解。为了提供更友好的使用效果，增加故障诊断功能，自动分析报文生命周期来给出故障原因以及解决办法。

