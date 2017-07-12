#! /usr/bin/env python
# -*- coding=utf-8
# Author : k2yk

import sqlite3
import config
import hashlib

class steamInfo:
    def __init__(self,domain = None,src=None,dst =None ,srcPort = -1 ,dstPort = -1):
        self.src = src
        self.srcPort = str(srcPort)
        self.dst = dst
        self.dstPort = str(dstPort)
        self.dstDomain = str(domain)
        self.steamIDsrc = ''
        self.steamIDdst = ''

        self.srcPack = []
        self.dstPack = []

        self.srcLastTime = ''
        self.dstLastTime = ''

        self.id = self.__initid()

    def __str__(self):
        temp = 'src:'+  self.src +' srcPort :' + self.srcPort

        temp += ' dst:'+  self.dst +' dstPort :' + self.dstPort+'\n'

        # temp = 'src:'+  self.src +'\n'
        return temp

    def __initid(self):
        if str(self.dstPort) == '443':
            temp = hashlib.md5((self.src+'|'+self.dst).encode('utf-8')).hexdigest()
            temp = str(self.srcPort)+'|'+temp
        else:
            temp = hashlib.md5((self.dst + '|' + self.src).encode('utf-8')).hexdigest()
            temp = str(self.dstPort) + '|' + temp
        return temp[:32]

    def save(self):
        pass

class resourcePool:
    def __init__(self):
        self.steamPool = {}
        self.savePath = config.SAVEPATH

    def poolNew(self,steamid,steamInfod):
        try:
            if not self.poolAsk(steamid):
                self.steamPool[steamid] = steamInfod
                return True
        except:
            return False
        return False

    def poolAdd(self,steamid,src = None,pack = None):
        try:
            if self.poolAsk(steamid):
                # temp = self.steamPool[steamid]
                temp = steamInfo()
                if src == self.steamPool[steamid].src:
                    self.steamPool[steamid].srcPack.append(pack)
                else:
                    self.steamPool[steamid].dstPack.append(pack)
                return True
        except:
            return False
        return False

    def poolAsk(self,steamid):
        try:
            if steamid in self.steamPool.keys():
                return True
        except:
            return False
        return False

    def poolSave(self,steamid):
        try:
            if steamid in self.steamPool.keys():
                tempData = self.steamPool[steamid]
                # tempData = steamInfo()
                domain = tempData.dstDomain
                dstPack = str(tempData.dstPack)
                srcPack = tempData.srcPack
                src = tempData.src
                dst = tempData.dst
                if '474, 11415, 8119, 13757' in dstPack or '475, 11416, 8120, 13758' in dstPack:
                    print('hit page uri : ctf.misterym.top/test1.html')
                if len(dstPack) <= 1 or len(srcPack) <= 1:
                    pass
                else:
                    d = open(self.savePath,'a')
                    d.write(domain+str(srcPack)+'src'+src+str(dstPack)+'\n')
                    d.close()
                self.steamPool[steamid].dstPack=[]
                self.steamPool[steamid].srcPack=[]

            print (domain+str(srcPack)+'src'+src+str(dstPack)+'\n')
        except:
            return False
        return False



def checkSteam(src = None,dst = None ,srcPort = -1 ,dstPort = -1):
    # if srcPort == -1 or dstPort == -1:
    #     return None
    if str(dstPort) == '443' :
        temp = hashlib.md5((src + '|' +dst).encode('utf-8')).hexdigest()
        temp = str(srcPort) + '|' + temp
        temp =  temp[:32]
        if config.RESOURCEPOOL.poolAsk(temp):
            return temp
    elif str(srcPort) == '443':
        temp = hashlib.md5((dst + '|' + src).encode('utf-  8')).hexdigest()
        temp = str(dstPort) + '|' + temp
        temp = temp[:32]
        if config.RESOURCEPOOL.poolAsk(temp):
            return temp

    return False
