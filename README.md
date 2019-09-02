# PenetrationTest代码介绍

### （1）zombie_scan

僵尸扫描脚本，利用僵尸机对目标服务器进行端口扫描以达到隐蔽自身的目的

- 使用了地址欺骗
- 需要自己寻找僵尸机

### （2）traceroute

模拟Linux下的traceroute命令对目标设备进行路由追踪。原理是使用了TTL的生存周期为0时，最终端设备会返回传递的数据包。

