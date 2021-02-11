# Antenna

Monitor 802.11 probe requests

## Install

Antenna requires Scapy in order to work, install using:
```bash
apt install python3-scapy
```

# Quickstart

Put the wireless interface in monitor mode and create a logs/ directory before starting Antenna.

Run using:
```bash
sudo python3 antenna.py monitor --interface wlan0mon
```
