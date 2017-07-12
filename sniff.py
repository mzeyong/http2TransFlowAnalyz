#! /usr/bin/env python
# -*- coding=utf-8  -*-
# Author : k2yk
import socket
import interpreter
# import cn
# import binascii
import time


class sniffer:
    def __init__(self,mode = 'debug'):
        self.method = interpreter.par()
        self.tempID=[]
        self.lockSteam=[]
        self.stopSignal=False
        self.socketLayer = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))
        self.offsetDict = {}
        if mode=='run':
            self.run()
        elif mode == 'debug':
            self.debug()
        else:
            return False


    def run(self):
        pass

    def debug(self):
        try:
            while not self.stopSignal:
                rawData , addr = self.socketLayer.recvfrom(65535)
                protorol , ethData = self.method.ethFrameP(rawData)
                if protorol == 8 and len(ethData) >20:
                    version ,length ,proto ,srcIp , dstIp ,ipData = self.method.ipUnPack(ethData)

                    if proto == 6 and len(ipData) >= 20:
                        srcPort , dstPort , seq ,ack ,tcpData = self.method.tcpUnPack(ipData)

                        if srcPort == 443 or dstPort == 443:
                            if len(tcpData) >= 6:
                                if srcPort == 443:
                                    self.offsetDict[dstIp + '|' + str(dstPort)] = self.method.tlsUnPack('\t\t', tcpData,0,b'',srcIp,srcPort,dstIp,dstPort)
                                if dstPort == 443:
                                    self.offsetDict[srcIp + '|' + str(srcPort)]= self.method.tlsUnPack('\t\t', tcpData,0,b'',srcIp,srcPort,dstIp,dstPort)
        except:
            pass
 

if __name__ == '__main__':
    sniffer()
