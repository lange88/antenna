import time
import yaml
import datetime
import argparse
import sys
import logging
import logging.config
from scapy.sendrecv import sniff
from scapy.layers.dot11 import Dot11ProbeReq, Dot11ProbeResp, Dot11Beacon

LOGGING_CONFIG = 'logging.yaml'
logger = logging.getLogger(__name__)

class Antenna(object):
    def __init__(self):
        Antenna.setup_logging()
        logger.debug("Application started")
        parser = argparse.ArgumentParser(description='Antenna', 
            usage="'antenna.py <command> [<args>]'")
        parser.add_argument('command', help="Subcommand to run")
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            logger.info("Unrecognized command")
            parser.print_help()
            exit(1)
        getattr(self, args.command)()


    def monitor(self):
        parser = argparse.ArgumentParser(
            description="Start the Antenna")
        parser.add_argument('--interface', required=True, default="wlan0mon", 
            help="Interface name to start monitoring")
        args = parser.parse_args(sys.argv[2:])

        try:
            sniff(iface=args.interface, prn=self.packet_callback)
        except Exception as e:
            logger.error(f"Error starting sniffer: {e}")


    def packet_callback(self, packet):
        # probe request packets
        if packet.type == 0 and packet.subtype == 4:
            if packet.info.decode('utf-8') == "":
                logger.info(f"Probe Broadcast > {packet.addr2}")
            else:
                logger.info(f"Probe Request > {packet.addr2} - {packet.info.decode('utf-8')}")
        #if packet.type == 0 and packet.subtype == 8:
        #    logger.info(f"Beacon > {packet.addr2} > {packet.info.decode('utf-8')}")


    @staticmethod
    def setup_logging():
        try:
            with open(LOGGING_CONFIG, 'rt') as configfile:
                config = yaml.safe_load(configfile.read())
            logging.config.dictConfig(config)
        except IOError or OSError:
            logging.basicConfig(level=logging.INFO)
            logging.warning(f"Exception while trying to open logger configuration file: {LOGGING_CONFIG}, "
                            f"defaulting to console")


if __name__ == "__main__":
    Antenna()