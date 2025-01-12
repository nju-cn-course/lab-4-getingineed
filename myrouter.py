#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''
from switchyard.lib.address import *
import time
import switchyard
import copy
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.lst={}
        self.fw_tb=[]
        self.get_fwtb()
        self.wait_lst=[]
    
    def get_fwtb(self):
        with open('forwarding_table.txt','r') as f:
            self.fw_tb=f.read().split('\n')
        for i in range(len(self.fw_tb)):
            self.fw_tb[i]=self.fw_tb[i].split()
            self.fw_tb[i][0]=IPv4Network(self.fw_tb[i][0]+"/"+self.fw_tb[i][1])
            self.fw_tb[i][1]=self.fw_tb[i][0].prefixlen
       # log_info('s1')
        for i in self.net.interfaces():
            ip_cur=str(IPv4Network(int(i.ipaddr)&int(i.netmask))).split('/')[0]+'/'+str(i.netmask)
            #log_info(ip_cur)
            self.fw_tb.append([IPv4Network(ip_cur),IPv4Network(ip_cur).prefixlen,'0.0.0.0',i.name])
        self.fw_tb.sort(key=lambda x:-x[1])
       # log_info('s2')

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
       
        timestamp, ifaceName, packet = recv
        arp=packet.get_header(Arp)
        if arp:
            try:
                if self.lst[arp.senderprotoaddr]!=arp.senderhwaddr:
                    if arp.senderhwaddr!='ff:ff:ff:ff:ff:ff':
                        #log_info('did differ')
                        self.lst[arp.senderprotoaddr]=arp.senderhwaddr
            except:
                if arp.senderhwaddr!='ff:ff:ff:ff:ff:ff':
                    self.lst[str(arp.senderprotoaddr)]=arp.senderhwaddr
                    #log_info(str(self.lst))
                    #log_info(str(self.wait_lst))
            try:
                due_itf=self.net.interface_by_ipaddr(arp.targetprotoaddr)
                if due_itf:
                    to_send=switchyard.lib.packet.create_ip_arp_reply(due_itf.ethaddr,arp.senderhwaddr,arp.targetprotoaddr,arp.senderprotoaddr)
                    self.net.send_packet(due_itf,to_send)
            except:
                pass
            self.renew_wt_lst()
        else:
            #log_info(packet.headers())
            #log_info(len(packet))
            ipV4=packet.get_header(IPv4)
            if ipV4:
                dst=ipV4.dst
                ipV4.ttl-=1
                sign=0
                for i in self.fw_tb:
                    #log_info(dst)
                    #log_info(i)
                    if dst in i[0]:
                       # log_info('222222112')
                        sign=1
                        nxt_ip=i[2] if i[2]!='0.0.0.0' else str(dst)
                        nxt_if=self.net.interface_by_name(i[3])
                        break
                #log_info('1212')
                if not sign:
                    log_info('fw_tb did not contain the dst_ip, drop')
                else:
                   # log_info('tnnd')
                    #log_info('1')
                    try:
                        #log_info('p1')
                        nxt_mac=self.lst[nxt_ip]
                        e=Ethernet()
                        e.src=nxt_if.ethaddr
                        e.dst=nxt_mac
                        p=Packet()
                        #log_info(packet.headers())
                        for j in range(2,len(packet.headers())):
                            log_info(j)
                            log_info(len(packet.headers())-j+1)
                           # log_info('md1'+str(packet[len(packet)-j+1]))
                            p.prepend_header(packet[len(packet.headers())-j+1])
                        p.prepend_header(ipV4)
                        p.prepend_header(e)
                        self.net.send_packet(nxt_if,p)
                        #log_info('2')
                    except:
                        #log_info('3')
                        #log_info('p2')
                        arp_req=switchyard.lib.packet.create_ip_arp_request(nxt_if.ethaddr,nxt_if.ipaddr,nxt_ip)
                        #log_info('mmtd')
                        self.net.send_packet(nxt_if,arp_req)

                        self.wait_lst.append([packet,nxt_ip,ipV4,nxt_if,time.time(),1])


    def renew_wt_lst(self):
        temp=[]
        for i in range(len(self.wait_lst)):
            try:
                nxt_mac=self.lst[self.wait_lst[i][1]]
                #log_info('in')
                #log_info('got')
                e=Ethernet()
                e.dst=nxt_mac
                e.src=self.wait_lst[i][3].ethaddr
                p=Packet()
                for j in range(2,len(self.wait_lst[i][0].headers())):
                    log_info(j)
                    log_info(len(self.wait_lst[i][0].headers())-j+1)
                    #log_info('md'+str(self.wait_lst[i][0][len(self.wait_lst[i][0])-j+1]))
                    p.prepend_header(self.wait_lst[i][0][len(self.wait_lst[i][0].headers())-j+1])
                p.prepend_header(self.wait_lst[i][2])
                p.prepend_header(e)
                self.net.send_packet(self.wait_lst[i][3],p)
                #log_info('out')
            except:
                t=time.time()
                #log_info(t)
                if t-self.wait_lst[i][-2]>=1*self.wait_lst[i][-1]:
                    #log_info('resd')
                    if self.wait_lst[i][-1]<5:
                        arp_req=switchyard.lib.packet.create_ip_arp_request(self.wait_lst[i][3].ethaddr,self.wait_lst[i][3].ipaddr,self.wait_lst[i][1])
                        self.net.send_packet(self.wait_lst[i][3],arp_req)
                        self.wait_lst[i][-1]+=1
                        temp.append(self.wait_lst[i])
                else:
                    temp.append(self.wait_lst[i])
        self.wait_lst=copy.deepcopy(temp)
       # log_info(self.wait_lst)

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            self.renew_wt_lst()
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
