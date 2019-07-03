# eternalrelayx

## about

Read about EternalRelay here:

 * https://medium.com/@technicalsyn/eternalrelayx-py-non-admin-ntlm-relaying-eternalblue-exploitation-dab9e2b97337

## dependencies

 * impacket (https://www.github.com/SecureAuthCorp/impacket)
 * MS17-010 (https://github.com/SecureAuthCorp/worawit/MS17-010)

## installation

 * cd <path to eternalrelayx project folder>
 * pip install -r requirements.txt
 * cd impacket && python setup.py install
 * eternalrelayx.py --help

## usage

 * eternalrelayx.py -t smb://10.10.10.1 -w --exploit

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
