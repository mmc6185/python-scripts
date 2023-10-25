#!/usr/bin/env python

import subprocess

interface = "eth0"
new_mac = input("Mac adresi girin : ")

print("[+] Changing MAC address for " + interface + " to " + new_mac)

subprocess.call(["ifconfig", interface, "down"], shell=True)
subprocess.call(["ifconfig", interface, "hw", "ether", new_mac], shell=True)
subprocess.call(["ifconfig", interface, "up"], shell=True)





