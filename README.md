# ourosdemo_linux
learn the source code of nmap

这是我们的主动探测linux版本，目前在ubuntu上测试通过。
仿照nmap源代码写的，主要分为主机发现，端口扫描，操作系统探测。
参数为单个主机ip地址，或者是网络地址（加上网络前缀）。

不需要预装什么东西，编译即可运行，使用libpcap的静态库进行链接。

潜在问题：包构造问题。nmap源码中使用条件编译语句来控制数据包的头部构造，我根据实际情况去除了一些。
有些宏定义，根本不知道会在什么地方出现。 = =||