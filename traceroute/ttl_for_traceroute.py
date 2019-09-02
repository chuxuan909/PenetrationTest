#!/usr/bin/env python
# -*- coding:utf-8 -*-
#Author：chenjie
#Email：soft-chenjie@foxmail.com
#Note：利用TTL来实现对目标IP的路由追踪
#使用了TTL无剩余生存时间则被路由设备回包的原理
#Vsersion：demo
from __future__ import print_function
import sys
import argparse
import re
import time

from scapy.all import *

#Python2.x的中文支持
reload(sys)
sys.setdefaultencoding('utf-8')

def green(strings):
    return "\033[1;32m %s \033[0m" % strings

def check_ip(ip):
    '''
    ip格式化检测
    :param ip:
    :return:
    '''
    pattern_ip = re.compile(r'(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})(\.(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})){3}')
    if not re.match(pattern_ip,ip):
        print("IP不符合规范")
        sys.exit(111)
    else:
        return re.match(pattern_ip, ip).group()

def parser_flag():
    '''
    参数选项定义
    '''
    #帮助信息
    parser=argparse.ArgumentParser(description="输入需要追踪的目标IP地址")
    #目标IP位置变量
    parser.add_argument("destination",help="需要追踪的目标IP")

    #获取参数
    # args=parser.parse_args()
    return parser.parse_args()


class TTL_TRACEROUTE(object):
    '''
    使用TTL原理执行路由追踪的类
    建议另存为模块，然后导入
    '''
    def __init__(self,destination,DEFAULT_MAX_TTL=1001):
        '''
        :param destination: 需要追踪的目标IP
        :param DEFAULT_MAX_TTL: 默认TTL的值从1开始增加到的最大值
        '''
        self.dst=destination
        self.ttl=DEFAULT_MAX_TTL

    def __send_ttl_ping(self,ttl,timeout=3):
        '''
        发送特定ttl值的ping包
        '''
        pkt = IP(dst=self.dst,ttl=ttl)/ICMP(type=8,code=0)  #type=8,code=0表示ping的request包，这是默认值也可以不写

        try:
            res=sr1(pkt,timeout=timeout)
            self.__put_file(res.src, ttl)
            if res.src == self.dst:
                print("已到达最终IP: ",end=" ")
                print(res.src)
                sys.exit(0)
            else:
                print("当前网络链路路由节点IP为: ",end=" ")
                print(res.src)
        except Exception as err:
            print("数据未能到达最终IP")
            print(err)
            sys.exit(312)

    def ttl_trace(self):
        '''
        使用ttl原理开始路由追踪
        :return:
        '''
        for trace in range(1,self.ttl):
            self.__send_ttl_ping(trace)

    def __put_file(self,dev_ip,ttl):
        '''
        写入当前跳数和ip地址到文件中
        :param ttl: 当前的ttl值，即当前跳数
        '''
        if not dev_ip:  #设备隐藏ip的情况
            dev_ip = "*"
        with open('./trace.log','w') as f:
            f.write("============%s===============\n" % time.strftime("%Y-%m-%d %H:%M", time.localtime()) )
            f.write("跳数\t\t\t路由节点P\n")
            f.write("%s\t\t\t%s\n" % (ttl,dev_ip))
            f.write("===================END=====================\n")

def main():
    '''主函数'''
    args=parser_flag()
    #IP地址的格式检测
    args.destination=check_ip(args.destination)  #这样写是为了将如"192.168.1.0XXX"这类的IP规范为"192.168.1.0"


    # 调试
    # print("传入类的变量为：")
    # print("目标IP",args.destination)

    #开始路由追踪
    my_trace=TTL_TRACEROUTE(args.destination)
    my_trace.ttl_trace()


if __name__ == "__main__":
    main()
