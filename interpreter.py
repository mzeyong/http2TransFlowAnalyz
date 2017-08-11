#! /usr/bin/env python
# -*- coding : utf - 8
# Author : k2yk
import re
import socket
import struct
import binascii
import config
import textwrap


import steamResource as packetInfo
#
# def forkPack():
#     results2 = pool.map(set, urls)

class par:
    def __init__(self):
        config.init()

    @staticmethod
    def ethFrameP(data):
        dstMac, srcMac, proto = struct.unpack("!6s6sH", data[:14])
        return socket.htons(proto), data[14:]

    @staticmethod
    def getMacAddr(bytesAddr):
        bytes_str = map("{:02x}".format, bytesAddr)
        return ':'.join(bytes_str).upper()

    @staticmethod
    def ipUnPack(data):
        versionHeaderLength = data[0]
        version = versionHeaderLength >> 4
        headerLength = (versionHeaderLength & 15) * 4
        ttl, proto, src, dst = struct.unpack('! 8x B B 2x 4s 4s', data[:headerLength])
        return version, headerLength, proto, par.ipv4(src), par.ipv4(dst), data[headerLength:]

    @staticmethod
    def ipv4(bytesAddr):
        return '.'.join(map(str, bytesAddr))

    @staticmethod
    def tcpUnPack(data):
        srcPort, dstPort, seq, ack, lengthFlag = struct.unpack('! H H L L H', data[:14])
        offset = (lengthFlag >> 12) * 4

        return srcPort, dstPort, seq, ack, data[offset:]

    @staticmethod
    def tls_version(version):  # 参数version是两字符
        bytes_str = map("{:02x}".format, version)
        formatted_str = ''.join(bytes_str)

        if formatted_str == "0301":
            formatted_str = 'TLS1.0 (0x' + formatted_str + ')'
        if formatted_str == "0302":
            formatted_str = 'TLS1.1 (0x' + formatted_str + ')'
        if formatted_str == "0303":
            formatted_str = 'TLS1.2 (0x' + formatted_str + ')'
        return formatted_str

    @staticmethod
    def get_cipher_suite(bytes_suit):
        hex_value = binascii.hexlify(bytes_suit)
        if hex_value.decode() in config.crypto_suites:
            return config.crypto_suites[hex_value.decode()] + "(0x{})".format(hex_value.decode())
        return '0x' + hex_value.decode()

    @staticmethod
    def tlsUnPack(prefix, data, offset=0, tlsHeader=b'', src=None, srcPort = -1, dst=None ,dstPort = -1):
        if offset > len(data):
            #		file.write("offset from segment : " + str(offset) + '\n')
            return [offset - len(data), b'']
        cursor = offset
        if not src or not dst:
            return [0,b'']


        if len(data[cursor:]) >= 5:
            contentType, minTlsVersion, length = struct.unpack("! B 2s H",
                                                               tlsHeader + data[cursor:cursor + 5 - len(tlsHeader)])
            cursor = cursor + 5 - len(tlsHeader)

            if contentType == 22:
                tempd = str(data)
                upgradeFlag = False
                signFlag = False
                if config.UPGRADEASKRULE in tempd :
                    upgradeFlag = True
                if config.UPGRADERULE in tempd:
                    signFlag = True

                if signFlag :
                    if upgradeFlag:
                        config.TEMPDICT[src+'|'+str(srcPort)] = dst
                        domainT = re.search(config.DOMAINRULE, tempd).group()
                        if '\x10' in domainT[:4] or 'x10' in domainT[:4]:
                            domainT = domainT[3:]
                        else:
                            domainT = domainT[1:]
                        config.TEMPDOMAINDICT[src+'|'+str(srcPort)] =domainT

                    else:
                        if dstPort == -1 or srcPort == -1:
                            return par.tls_multiple_praise(length, cursor, data, dst=dst, src=src,dstPort = dstPort , srcPort = srcPort)
                        if dst+'|'+str(dstPort) in config.TEMPDICT.keys():
                            domain = config.TEMPDOMAINDICT[dst+'|'+str(dstPort)]
                            pid = packetInfo.checkSteam(src = dst ,dst = src,srcPort = dstPort , dstPort = srcPort)
                            if not pid :
                                pack = packetInfo.steamInfo(domain = domain,src = dst ,dst = src,srcPort = dstPort , dstPort = srcPort)
                                saveState = config.RESOURCEPOOL.poolNew(pack.id,pack)
                                if saveState :
                                    print ('new steam connect')
                        elif src + '|' + str(srcPort) in config.TEMPDICT.keys():
                            domain = config.TEMPDOMAINDICT[src + '|' + str(srcPort)]
                            pid = packetInfo.checkSteam(src=src, dst=dst, srcPort=srcPort, dstPort=dstPort)
                            if not pid:
                                pack = packetInfo.steamInfo(domain=domain, src=src, dst=dst,
                                                            srcPort=srcPort, dstPort=dstPort)
                                saveState = config.RESOURCEPOOL.poolNew(pack.id, pack)
                                if saveState:
                                    print('new steam connect')
                        
            if contentType == 23:
                packid = packetInfo.checkSteam(src = src ,dst = dst,srcPort = srcPort , dstPort = dstPort)

                if packid:
                    # print(length)
                    # config.RESOURCEPOOL.steamPool[packid].srcPack.append(length)
                    # steamInfod = config.RESOURCEPOOL.steamPool[packid]
                    if  str(dstPort) == '443' :
                        if length < 65:
                            pass
                        else:
                            config.RESOURCEPOOL.steamPool[packid].srcPack.append(length)
                    elif str(srcPort) == '443':
                        if length <65:
                            pass
                        else:
                            config.RESOURCEPOOL.steamPool[packid].dstPack.append(length)
                    if length == 41 or length == 0:
                        config.RESOURCEPOOL.poolSave(packid)
   

            return [0, b'']
        elif (len(data[cursor:]) > 0) and data[cursor] == 23:  # 这才是分片的关键 tls一个头部可能会被藏在两个分片中，需要判断第一个是否\x17
            return [0, data[cursor:]]
        else:
            return [0, b'']


    @staticmethod
    def tls_multiple_praise(tlsLength, cursor, data, dst=None, src=None, srcPort = -1 , dstPort = -1):
        if tlsLength >= len(data[cursor:]):
            return [tlsLength - len(data[cursor:]), b'']
        else:
            return par.tlsUnPack(config.DATA_TAB_3, data, cursor + tlsLength,src=src,dst=dst)


    @staticmethod
    def formatMultiLine(prefix, string, size=80):
        size -= len(prefix)
        if isinstance(string, bytes):
            dataStr = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(dataStr, size)])
