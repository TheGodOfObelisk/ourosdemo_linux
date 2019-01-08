# ourosdemo_linux
learn the source code of nmap

这是我们的主动探测linux版本，目前在ubuntu16.04上测试通过。
仿照nmap源代码写的，主要分为主机发现，端口扫描，操作系统探测。
参数为单个主机ip地址，或者是网络地址（加上网络前缀）。

不需要预装什么东西，编译即可运行，使用libpcap的静态库进行链接(libpcap.a)。
