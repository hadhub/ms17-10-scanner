#!/usr/bin/python3
import nmap
import argparse
import os

def main():
    Parser = argparse.ArgumentParser()
    Parser.add_argument("-ip", help="Sepcify IP", required=True)
    Args = Parser.parse_args()
    IPADDR = Args.ip
    print(f"[i] Scanning : {IPADDR}")
    nmapScan(IPADDR)

def nmapScan(IPADDR):
    Scanner = nmap.PortScanner()
    SambaScanner = nmap.PortScanner()
    Scanner.scan(hosts=IPADDR, arguments='-T4')
    for hosts in Scanner.all_hosts():
        ports = Scanner[hosts].all_tcp()
        print(f"{hosts} is up!")
        print(f"Ports : {ports}")
        if Scanner[hosts].has_tcp(445):
            SambaScanner.scan(hosts=hosts,ports='445',arguments=f'--script smb-vuln-ms17-010 -oN /tmp/report.txt')
            print("445 OPEN ! Checking for MS17-10\n")
            print("[i] Using smb-vuln-ms17-010...\n")
            os.system('/usr/bin/cat /tmp/report.txt | /usr/bin/grep "^|"')
            os.remove(f'/tmp/report.txt')

if __name__ == '__main__':
    main()
