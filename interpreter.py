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
        # flag_urg = (lengthFlag & 32) >> 5
        # flag_ack = (lengthFlag & 16) >> 4
        # flag_psh = (lengthFlag & 8) >> 3
        # flag_rst = (lengthFlag & 4) >> 2
        # flag_syn = (lengthFlag & 2) >> 1
        # flag_fin = lengthFlag & 1

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

            # if '23.225.207.168' in (src, dst):
            #     print(length)

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
                            # else:
                            #     pack = config.RESOURCEPOOL.poolAdd(pid,src=src,dst=dst,pack = length)
                            #     if pack :
                            #         print ('connected success')
                # tempddd = str(data)
                # domains = re.search(config.DOMAINRULE, tempddd)
                # flagupgrade = re.search(config.UPGRADEASKRULE, tempddd)
                # flag = re.search(config.UPGRADERULE, tempddd)
                # if domains:
                #     domainResult = domains.group()
                #     if domainResult.find('x10') == 0:E
                #         domainResult = domainResult[3:]
                #     else:
                #         domainResult = domainResult[1:]
                #     if len(domainResult) > 5:
                #         if not flagupgrade and flag:
                #             if src not in RESOURCE.clientList:
                #                 RESOURCE.clientList.append(src)
                #             if dst not in RESOURCE.serverList:
                #                 RESOURCE.serverList.append(src)
                #             if src in RESOURCE.anayzDict.keys():
                #                 if domainResult not in RESOURCE.anayzDict[src][dst]['domain'].keys():
                #                     RESOURCE.anayzDict[src][dst]['domain'][domainResult] = True
                #                 RESOURCE.anayzDict[src][dst]['tempDATA'] = []
                #             else:
                #                 if src:
                #                     RESOURCE.anayzDict[src] = {dst: {'tempDATA': [], 'domain': {}, 'result': {}}}
                #                     RESOURCE.anayzDict[src][dst]['domain'][domainResult] = True
                #         print(RESOURCE.anayzDict)
                # tempddd = data[str(data).find('\x00\x10'):str(data).find('\x00\x17')])
                # if 5 < length:
                #     # tempddd = str(data)
                #     print(data)
                #     # res1 = re.search(UPGRADEASKRULE, tempddd)
                #     # print(res1)
                #     # res1 = re.search(UPGRADERULE, tempddd)
                #     # print(res1)
                #     handShakeType, handShakeLength = struct.unpack("! B I", data[cursor:cursor + 5])
                #
                #     lenHand = handShakeLength >> 8
                #
                #     if handShakeType == 1:
                #         pass
                #         # par.handle_client_hello(config.DATA_TAB_4, data[cursor + 4:], lenHand)  # 从版本号开始分析 为了解决3bytes的数据
                #     elif handShakeType == 2:
                #         pass
                #         # par.handle_server_hello(config.DATA_TAB_4, data[cursor + 4:], lenHand)
                #     else:
                #         pass

                # return par.tls_multiple_praise(length, cursor, data, dst=dst, src=src,srcPort = dstPort , dstPort = srcPort)

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
                #
                # # file.write("tls version : "+tls_version(minTlsVersion)+"  "+"TLSlength:" + str(length) +" " +"TCPLength:"+str(len(data)) +' '+'offset : ' + str(offset) +"\n")
                # # print("TLS content Type :%d" % contentType)
                # # print("TLS version :%s" % tls_version(minTlsVersion))
                # # print("TLS Length : %d" % length)
                # # try:
                # #     if length == 41:
                # #         if src in RESOURCE.serverList:
                # #             if len(RESOURCE.anayzDict[src][dst]['tempDATA']) > 0:
                # #                 RESOURCE.anayzDict[src][dst]['result'][
                # #                     str(RESOURCE.anayzDict[src][dst]['tempDATA'])] = True
                # #                 RESOURCE.anayzDict[src][dst]['tempDATA'] = []
                # #         elif dst in RESOURCE.serverList:
                # #             if len(RESOURCE.anayzDict[dst][src]['tempDATA']) > 0:
                # #                 RESOURCE.anayzDict[dst][src]['result'][
                # #                     str(RESOURCE.anayzDict[src][dst]['tempDATA'])] = True
                # #                 RESOURCE.anayzDict[dst][src]['tempDATA'] = []
                # #     else:
                # #         if src in RESOURCE.serverList:
                # #             RESOURCE.anayzDict[src][dst]['tempDATA'].append(length)
                # #         elif dst in RESOURCE.serverList:
                # #             RESOURCE.anayzDict[dst][src]['tempDATA'].append(length)
                # # except Exception as Error:
                # #     print(Error)
                # # print(RESOURCE.anayzDict)
                # return par.tls_multiple_praise(length, cursor, data, dst=dst, src=src,srcPort = srcPort , dstPort = dstPort)

            ########################################################


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