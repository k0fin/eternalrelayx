# eternalrelayx

## about

Read about EternalRelay here:

 * https://medium.com/@technicalsyn/eternalrelayx-py-non-admin-ntlm-relaying-eternalblue-exploitation-dab9e2b97337


## dependencies
 * impacket     (https://www.github.com/SecureAuthCorp/impacket)
 * MS17-010     (https://github.com/SecureAuthCorp/worawit/MS17-010)

## recommended 3rd-party tools
 * CrackMapExec (https://github.com/byt3bl33d3r/CrackMapExec.git)

   - A super awesome tool written by byt3bl33d3r (an amazing contributor to the community) which is used in the EternalRelay blog demo
     to generate a list file of NTLM relay targets.

   - NOTE: Only CME 4.0.1+ supports the --gen-relay-list option, so be sure you aren't attempting to follow along with the demo with an earlier
     version (Credits to @SourceFrenchy for pointing that out, thanks dude! :D )

## supported distros

 * Tested and supported on Kali 4.19.0-kali5-amd64

## installation

 * cd <path to eternalrelayx project folder> (I was using /opt for the demo, which made my eternalrelayx working directory /opt/eternalrelayx)
 * pip install -r requirements.txt
 * cd impacket && python setup.py install
 * eternalrelayx.py --help

## usage

 * Single target
    eternalrelayx.py -t "smb://10.10.10.1" --exploit

 * Multiple targets
    eternalrelayx.py -tf relays.txt -w --exploit

## todo

 * Integrate zzz_exploit.py for drastically increased exploitation reliability.
 * Integrate checker.py functionality to integrate detection of MS17-010 without attacking hosts.
 * Increase error handling and logic

## credits

 * Dirkjanm
 * Alberto Solino
 * Worawit Wang
 * Skip Duckwall
 * Tyler Robinson
