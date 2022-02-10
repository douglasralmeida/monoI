from scapy.all import *

print("sending cruzeiro")
answer = sr1(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="cruzeiro")),verbose=1)
print(answer.summary())

print("sending botafogo")
answer = sr1(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="botafogo")),verbose=1)
print(answer.summary())
