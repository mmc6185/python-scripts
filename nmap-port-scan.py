#!/usr/bin/env python3

import nmap
import re

ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")

def print_header():
    print(r"""
  ____                  _               _             
 / ___|  ___  _ __ ___ (_) ___  _ __   (_) ___  _ __  
 \___ \ / _ \| '_ ` _ \| |/ _ \| '_ \  | |/ _ \| '_ \ 
  ___) | (_) | | | | | | | (_) | | | | | | (_) | | | |
 |____/ \___/|_| |_| |_|_|\___/|_| |_|_|_|\___/|_| |_|""")

def get_ip_address():
    while True:
        ip = input("\nLütfen taramak istediğiniz IP adresini girin: ")
        if ip_add_pattern.search(ip):
            print(f"{ip} geçerli bir IP adresi")
            return ip
        print("Geçersiz IP adresi. Lütfen geçerli bir IPv4 adresi girin (örneğin, 192.168.1.1).")

def get_port_range():
    port_min, port_max = 0, 65535
    while True:
        print("Lütfen taramak istediğiniz port aralığını <baş>-<bitiş> formatında girin (örneğin, 60-120)")
        port_range = input("Port aralığını girin: ").replace(" ", "")
        match = port_range_pattern.search(port_range)
        if match:
            port_min = int(match.group(1))
            port_max = int(match.group(2))
            if 0 <= port_min <= port_max <= 65535:
                return port_min, port_max
        print(f"Geçersiz aralık. Portlar 0 ile 65535 arasında olmalı ve <baş>-<bitiş> formatında olmalı.")

def scan_ports(ip, port_min, port_max):
    nm = nmap.PortScanner()
    print(f"\nTarama yapılıyor: IP: {ip} (Portlar: {port_min}-{port_max})")
    for port in range(port_min, port_max + 1):
        try:
            result = nm.scan(ip, str(port))
            port_status = result['scan'][ip]['tcp'][port]['state']
            print(f"Port {port}: {port_status}")
        except KeyError:
            print(f"Port {port}: Durum belirlenemedi (muhtemelen filtrelenmiş veya kapalı).")
        except Exception as e:
            print(f"Port {port}: Tarama başarısız (Hata: {str(e)}).")

def main():
    print_header()
    ip = get_ip_address()
    port_min, port_max = get_port_range()
    scan_ports(ip, port_min, port_max)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nTarama kullanıcı tarafından kesildi. Çıkılıyor...")
    except Exception as e:
        print(f"\nBeklenmedik bir hata oluştu: {str(e)}")
