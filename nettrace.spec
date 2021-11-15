Summary: A skb (network package) trace tool for kernel

Name: nettrace

Version: 0.1.1

Release: 2.tl3

License: GPL

BuildRoot:%{_tmppath}/%{name}-%{version}-%{release}-root

Group: Development/Tools

Source0:%{name}-%{version}.tar.gz

# URL:

Requires:bcc >= 0.10.0, python-bcc >= 0.10.0

%description
nettrace is is a powerful tool to trace network packet and diagnose
network problem inside kernel on TencentOS.

It make use of eBPF and BCC.

'skb' is the struct that used in kernel to store network package.
By tracing kernel function and tracepoint (with the help of kprobe
based on eBPF) that handle skb, nettrace is able to show the path
of skb bypass inside kernel network stack. Therefor, some network
issue (such as package drop) can be solved simply.

%prep
%setup -q

%install
DESTDIR=$RPM_BUILD_ROOT/opt/nettrace/
rm -rf $RPM_BUILD_ROOT
mkdir -p $DESTDIR

cd /home/xm/project/nettrace/
cp nettrace.c $DESTDIR/
cp nettrace.py $DESTDIR/
cp if_indextoname.py $DESTDIR/
cp config.py $DESTDIR/
cp tracer.json $DESTDIR/

mkdir -p $RPM_BUILD_ROOT/usr/share/man/man8/
gzip nettrace.8
cp nettrace.8.gz $RPM_BUILD_ROOT/usr/share/man/man8/
gunzip nettrace.8.gz

mkdir -p $RPM_BUILD_ROOT/usr/share/bash-completion/completions/
cp bash-completion.sh $RPM_BUILD_ROOT/usr/share/bash-completion/completions/nettrace

mkdir -p $RPM_BUILD_ROOT/usr/sbin/
ln -s /opt/nettrace/nettrace.py $RPM_BUILD_ROOT/usr/sbin/nettrace

%files
%defattr (-,root,root,0755)
/opt/nettrace/
/usr/sbin/nettrace
/usr/share/man/man8/nettrace.8.gz
/usr/share/bash-completion/completions/nettrace

%doc

%changelog
