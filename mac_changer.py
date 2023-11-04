#!/usr/bin/env python

import subprocess
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", dest="interface", help="Interface to change its mac address")
parser.add_argument("-m", "--mac", dest="new_mac", help="New mac address")

parser.parse_args()

interface = input("Interface > ")
new_mac = input("Mac > ")

print("[+] Changing MAC address for " + interface + " to " + new_mac)


#Guvenlik zafiyetlerine sebep oluyor.
'''
subprocess.call("ifconfig " + interface + " down", shell=True)
subprocess.call("ifconfig " + interface + " hw" + " ether " + new_mac, shell=True)
subprocess.call("ifconfig " + interface + " up", shell=True)
'''

#Bu daha iyi
subprocess.call(["ifconfig", interface, "down"])
subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
subprocess.call(["ifconfig", interface, "up"])









