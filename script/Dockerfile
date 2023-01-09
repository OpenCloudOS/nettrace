FROM debian:sid

RUN rm -rf /etc/apt/sources.list.d/
RUN echo 'deb http://mirrors.tuna.tsinghua.edu.cn/debian/ sid main non-free contrib' > /etc/apt/sources.list

RUN apt update && apt upgrade -y

RUN apt install gcc clang llvm -y
RUN apt install make file bpftool libbpf-dev -y
RUN apt install rpm zip bzip2 -y

RUN apt clean
