#!/usr/bin/env python

import subprocess

mac = input("Mac adresi girin : ")

subprocess.call("ifconfig eth0 down", shell=True)

change_mac = "ifconfig eth0 hw ether " + mac
subprocess.call(change_mac, shell=True)
subprocess.call("ifconfig eth0 up", shell=True)

