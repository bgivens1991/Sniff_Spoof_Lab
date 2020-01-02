# -*- coding: utf-8 -*-
from scapy.all import *

a = IP()
a.src = "1.2.3.4" 
a.dst = "192.168.95.101" 
a.ttl = 10
b = ICMP() 
p = a/b 
send(p)
ls(a) 