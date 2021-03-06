Summary: A skb (network package) trace tool for kernel

Name: nettrace

Version: %{getenv:VERSION}

Release: %{getenv:RELEASE}

License: GPL

BuildRoot:%{_tmppath}/%{name}-%{version}-%{release}-root

Group: Development/Tools

Source0:%{name}-%{version}.tar.gz

# URL:

Requires:bcc,python3-bcc

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
rm -rf $RPM_BUILD_ROOT
make PREFIX=$RPM_BUILD_ROOT install
PREFIX=$RPM_BUILD_ROOT

%files
%defattr (-,root,root,0755)
/opt/nettrace/
/usr/bin/nettrace
/usr/bin/nettrace-legacy
/usr/bin/droptrace
/usr/bin/nodetrace-mark
/usr/bin/nodetrace-watch
/usr/share/man/man8/nettrace-legacy.8.gz
/usr/share/man/zh_CN/man8/nettrace.8.gz
/usr/share/man/man8/dropreason.8.gz
/usr/share/bash-completion/completions/nettrace
/usr/share/bash-completion/completions/droptrace

%doc

%changelog
