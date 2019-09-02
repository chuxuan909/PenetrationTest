#!/usr/bin/env python
# -*- coding:utf-8 -*-
#Author：chenjie
#Email：soft-chenjie@foxmail.com
#Note：僵尸扫描脚本
#使用僵尸机来扫描目标主机端口
#Vsersion：demo
import sys
import argparse
import json
import re

from scapy.all import *

#Python2.x的中文支持
reload(sys)
sys.setdefaultencoding('utf-8')

def green(strings):
    return "\033[1;32m %s \033[0m" % strings

def usage():
    '''
    输出帮助信息
    :return:
    '''
    print(
"""
Usage:  sys.args[0]       [option] 

[option]：

-h or --help：显示帮助信息
-z or --zombie：僵尸机IP                 例如：-z 192.168.0.191
-zp：僵尸机端口默认是135                 例如：-zp 80
-t or --target：目标主机IP               例如：-t 192.168.0.1
-tp：目标主机端口                        例如：-tp 443
-trp：扫描的目标主机端口范围，逗号分隔   例如：-tp 0,1024 
"""
    )

def argv_check():
    '''
    判断是否输入了参数
    :return:
    '''
    if len(sys.argv) == 1:
        usage()
        sys.exit()

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
    :return:
    '''
    #帮助信息
    parser=argparse.ArgumentParser(description="输入僵尸机和目标主机的ip端口")
    #僵尸机相关选项
    parser.add_argument("-z","--zombie",help="僵尸机IP              例如：-z 192.168.0.191")
    # parser.add_argument("zpp",type=int,help="僵尸机端口 默认是80",default=80)
    parser.add_argument("-zp",type=int,help="僵尸机端口默认是135    例如：-zp 80",default=135)
    #目标主机相关
    parser.add_argument("-t","--target",help="目标主机IP                例如：-t 192.168.0.1")
    parser.add_argument("-tp",type=int,help="扫描的目标主机端口,        例如：-tp 1024")
    parser.add_argument("-rtp",help="扫描的目标主机端口范围，逗号分隔   例如：-tp 0,1024 ")
    #获取参数
    # args=parser.parse_args()
    return parser.parse_args()


class ZombieScan(object):
    '''
    执行僵尸扫描的类
    建议另存为模块，然后导入
    '''
    def __init__(self,zombie_ip,zombie_port,target_ip,target_port):
        '''
        :param zombie_ip:   僵尸机ip 类型为字符串
        :param zombie_port: 僵尸机端口 类型为整数
        :param target_ip:   目标主机ip 类型为字符串
        :param target_port: 目标主机端口，类型为列表或集合
        :param THREAD_NUM:
        '''
        self.zip=zombie_ip
        self.tip=target_ip
        self.tpt=target_port
        self.zombiepkt=IP(dst=zombie_ip)/TCP(dport=zombie_port,flags="SA") #发送到僵尸机的数据包
        self.__zombie_check()

    def __senf_to_zombie(self,timeout=3):
        '''
        发送SYN/ACK数据包到僵尸机
        返回数据包实例
        '''
        try:
            resault=sr1(self.zombiepkt,timeout=timeout)
            if  resault:
                return resault
            else:
                print("未能收到僵尸主机数据包，发送超时")
                sys.exit(311)
        except Exception as err:
            print("未能发送数据包到僵尸主机",err)
            sys.exit(312)

    def __zombie_check(self):
        '''
        僵尸机是否能进行扫描的检查：
        连续发送2次SYV/ACK包到僵尸
        通过2次回包内的ipid是否差1来判断是该僵尸机否适合扫描
        '''
        res1=self.__senf_to_zombie()
        res2=self.__senf_to_zombie()
        if res2.id-res1.id != 1:
            print("你选的僵尸机不能准确的扫描出目标端口是否开放：")
            print("僵尸机ipid两次递增差值不为1")
            sys.exit(411)

    def __senf_to_target_single(self,dport):
        '''
        向目标主机发送伪装数据包
        :param dport: 目标主机被扫描的端口
        :return:
        '''
        try:
            dport = int(dport)
        except ValueError:
            print("请输入正确数据格式的端口")
            sys.exit(511)
        target_pkt=IP(src=self.zip,dst=self.tip)/TCP(dport=dport)
        send(target_pkt)

    def __zombie_scan_single(self,dport):
        '''
        僵尸扫描
        :param dport:  目标主机被扫描的端口
        :return: 返回两次ipid的差值
        '''
        res_z1 = self.__senf_to_zombie()
        self.__senf_to_target_single(dport)
        res_z2 = self.__senf_to_zombie()
        return res_z2.id-res_z1.id

    def ipid_judge(self,ipid_c,dport):
        if ipid_c == 2:
            print("端口 %s %s" % (dport,green("开放")))
            with open('./scan_resault.txt','a') as f:
                f.write("%s\t%s\n" % (dport,"Open"))
        else:
            print("端口 %s 未开放" % dport)

    def zombie_scan(self):
        if len(self.tpt) == 1:
            ipid_c=self.__zombie_scan_single(self.tpt[0])
            self.ipid_judge(ipid_c,self.tpt[0])
        elif len(self.tpt) == 2:
            try:
                start_num = int(self.tpt[0])
                end_num = int(self.tpt[1])+1
                for index_port in range(start_num,end_num):
                    ipid_c = self.__zombie_scan_single(index_port)
                    self.ipid_judge(ipid_c, index_port)
            except ValueError:
                print("请输入正确数据格式的端口")
                sys.exit(511)

def main():
    '''主函数'''
    argv_check()
    args=parser_flag()
    #IP地址的格式检测
    args.zombie=check_ip(args.zombie)
    args.target=check_ip(args.target)
    #目标主机的端口转换
    if args.rtp:
        li_tpt=args.rtp.split(",")
    else:
        li_tpt=[]
        li_tpt.append(args.tp)

    # 调试
    # print(args.zombie)
    # print(args.zp)
    # print(args.target)
    # print(args.tp)
    # print(args.rtp)
    # print("传入类的变量为：")
    # print("僵尸机IP",args.zombie)
    # print("僵尸机端口",args.zp)
    # print("目标机IP",args.target)
    # print("目标机端口",li_tpt)

    #开始扫描
    scaner = ZombieScan(args.zombie,args.zp,args.target,li_tpt)
    scaner.zombie_scan()


if __name__ == "__main__":
    main()
