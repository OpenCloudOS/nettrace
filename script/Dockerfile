FROM ubuntu
RUN sed -i 's|ports.ubuntu.com|mirrors.aliyun.com|g' /etc/apt/sources.list
RUN apt update && apt update -y

RUN apt install gcc clang llvm libbpf-dev make file linux-tools-virtual -y
RUN find /usr/lib/linux-tools/ -name bpftool | xargs -I % cp % /usr/bin/
RUN apt purge --auto-remove linux-tools-virtual -y
RUN apt clean
