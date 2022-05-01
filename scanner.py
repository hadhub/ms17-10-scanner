#!/usr/bin/python3
import nmap
import argparse
import os

def main():
    # Argument
    Parser = argparse.ArgumentParser()
    Parser.add_argument("-ip", help="Sepcify IP", required=True)
    Args = Parser.parse_args()
    IPADDR = Args.ip
    print(f"[i] Scanning : {IPADDR}")
    nmapScan(IPADDR)

def nmapScan(IPADDR):
    # Instanciations des objets
    Scanner = nmap.PortScanner()
    SambaScanner = nmap.PortScanner()
    # Premier scan avec -T4
    Scanner.scan(hosts=IPADDR, arguments='-T4')
    # Check si la target et up ou down
    for hosts in Scanner.all_hosts():
        print(f"{hosts} is up!")
        # Pour tout les hosts afficher les ports TCP
        for hosts in Scanner.all_hosts():
            print(f"{Scanner[hosts].all_tcp()}")
            # Si le port SMB(445) est ouvert
            if Scanner[hosts].has_tcp(445):
                print("445 OPEN ! Checking for MS17-10")
                # Début du premier scan avec un argument + création de fichier
                SambaScanner.scan(hosts=hosts,ports='445',arguments=f'--script smb-vuln-ms17-010 -oN /tmp/report.txt')
                # Ouverture fichier + affichage
                with open(f'/tmp/report.txt', 'r') as result:
                    lines = result.readlines()
                    for line in lines:
                        # Affichage
                        print(line)
                    # Suppression du fichier
                    os.remove(f'/tmp/report.txt')


if __name__ == '__main__':
    main()
