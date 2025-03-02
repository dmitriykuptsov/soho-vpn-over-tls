#!/usr/bin/python3

# Copyright (C) 2019 strangebit

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

__author__ = "Dmitriy Kuptsov"
__copyright__ = "Copyright 2020, strangebit"
__license__ = "GPL"
__version__ = "0.0.1a"
__maintainer__ = "Dmitriy Kuptsov"
__email__ = "dmitriy.kuptsov@gmail.com"
__status__ = "development"

# Network stuff
import socket
import ssl

# Add current directory to Python path
import sys
import os
sys.path.append(os.getcwd())

# Threading
import threading

# Structures
import struct

# Common helper classes
from common import packet
from common import database
from common import state
from common import pool
from common import tun
from common import utils
from common import tun
from common import routing
from common import dns
from common import nat

# Client configuration file
import config

# Exit hook
import atexit

import logging

# Configure logging to console and file
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("vpn.log")#,
        #logging.StreamHandler(sys.stdout)
    ]
);

# Timing
from time import sleep, time

def get_default_gateway():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                # If not default route or not RTF_GATEWAY, skip it
                continue

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

class Client():
	def __init__(self, config):
		"""
		Secure socket and state machine initialization
		"""
		self.ctx = ssl.create_default_context();
		if config.get("CA_CERTIFICATE"):
			self.ctx.load_verify_locations(config["CA_CERTIFICATE"]);
		hostname = config["SERVER_HOSTNAME"]
		if not config.get("SERVER_IP"):
			config["SERVER_IP"] = socket.gethostbyname(hostname)
			logging.debug("Using %s as server IP ..." % config["SERVER_IP"])
		self.sock = socket.create_connection((config["SERVER_IP"], config["SERVER_PORT"]));
		#self.sock.settimeout(30)
		self.ctx.check_hostname = True;
		self.secure_socket = self.ctx.wrap_socket(self.sock, server_hostname=hostname, server_side=False);
		self.sm = state.StateMachine();
		self.sm.connected();
		self.data_timeout = time() + config["DATA_TIMEOUT"];
		self.buffer_size = config["BUFFER_SIZE"];
		if not config.get("DEFAULT_GW"):
			config["DEFAULT_GW"] = get_default_gateway()
			if not config["DEFAULT_GW"]:
				raise Exception('Could not determine default gateway, please configure manually')
			logging.debug("Using %s as default gateway ..." % config["DEFAULT_GW"])
		self.default_gw = config["DEFAULT_GW"];
		self.dns_server = config["DNS_SERVER"];
		self.server_ip = config["SERVER_IP"];

		"""
		Initialize secure socket buffer
		"""
		self.secure_socket_buffer = [];

		"""
		Routing and DNS configurators
		"""
		self.routing_ = routing.Routing();
		self.dns_ = dns.DNS();
		self.nat_ = nat.NAT();

	"""
	Writes data to TUN interface
	"""
	def write_to_tun(self, payload):
		if not payload:
			return;
		self.tun.write(bytes(bytearray(payload)));

	"""
	Writes data packet into secure socket
	"""
	def write_to_secure_socket(self, payload):
		if not payload:
			return;
		#print("Got data on TUN interface");
		userdata = packet.DataPacket();
		#print("Writing %d bytes to socket" % (len(payload)))
		userdata.set_payload(payload);
		#print("Total packet length %d" % (len(userdata.get_buffer())));
		self.secure_socket.send(userdata.get_buffer());
		self.data_timeout = time() + config["DATA_TIMEOUT"];

	"""
	Reads data from secure socket
	"""
	def read_from_secure_socket(self):
		buf = bytearray(self.secure_socket.recv(self.buffer_size));
		if len(buf) == 0:
			raise Exception("Socket was closed");
		self.data_timeout = time() + config["DATA_TIMEOUT"];
		self.secure_socket_buffer += buf;
		if len(self.secure_socket_buffer) <= packet.Packet.get_header_length():
			return None;
		packet_length = packet.Packet.get_total_length(self.secure_socket_buffer);
		#print("Packet length %d" % (packet_length));
		if packet_length > len(self.secure_socket_buffer):
			return None;
		buf = self.secure_socket_buffer[0:packet_length];
		self.secure_socket_buffer = self.secure_socket_buffer[packet_length:];
		userdata = packet.DataPacket(buf);
		if userdata.get_type() != packet.PACKET_TYPE_DATA:
			return None;
		return userdata.get_payload();

	"""
	Reads data from TUN interface
	"""
	def read_from_tun(self):
		# https://stackoverflow.com/questions/43449664/why-the-leading-4bytes-data-missing-when-sending-raw-bytes-data-to-a-tap-device
		buf = bytearray(self.tun.read(self.tun_mtu));
		return buf;

	"""
	TUN read loop
	"""

	def tun_loop(self):
		logging.debug("Starting to read from TLS socket...")
		while self.sm != None and not self.sm.is_stalled():
			try:
				self.write_to_tun(self.read_from_secure_socket());
			except:
				logging.debug("Connection was closed in TUN loop, please restart the client...")
				#self.routing_.restore_default_route(self.default_gw);
				self.sm.stalled();
				self.tun.close();
		logging.debug("TUN loop completed...")

	"""
	TLS loop
	"""
	def tls_loop(self):
		logging.debug("Starting to read from tun device....")
		while self.sm != None and not self.sm.is_stalled():
			try:
				self.write_to_secure_socket(self.read_from_tun());
			except:
				logging.debug("Connection was closed TLS loop, please restart the client...");
				#self.routing_.restore_default_route(self.default_gw);
				self.sm.stalled();
				self.tun.close();
		logging.debug("TLS loop completed...")

	def status_loop(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.bind(("127.0.0.1", 9004))
		s.listen(5)
		while True:
			reading = True
			conn, addr = s.accept()
			while reading:
				command = conn.recv(100);
				command=command.decode("ASCII").strip()
				if command == "status":
					conn.send("Status: \n".encode("ASCII"))
					conn.send(("State: %s \n" % (str(self.sm))).encode("ASCII"))
					logging.critical("State: %s \n" % (str(self.sm)))
					print("State: %s \n" % (str(self.sm)))
				elif command.strip() == "exit" or command.strip() == "":
					conn.close();
					reading = False;
		s.close()

	"""
	Client's main loop
	"""
	def loop(self):
		while True:
			if self.sm.is_unknown():
				logging.debug("unknown....")
				continue;
			elif self.sm.is_connected():
				logging.debug("Sending authentication data...");
				p = packet.AuthenticationPacket();
				p.set_username(bytearray(config["USERNAME"], encoding="ASCII"));
				p.set_password(bytearray(config["PASSWORD"], encoding="ASCII"));
				self.secure_socket.send(p.get_buffer());
				self.sm.waiting_for_authentication();
			elif self.sm.is_waiting_for_authentication():
				buf = bytearray(self.secure_socket.recv(self.buffer_size));
				if len(buf) > 0:
					p = packet.Packet(buf);
					if p.get_type() == packet.PACKET_TYPE_ACK:
						logging.debug("Authentication succeeded...");
						self.sm.authenticated();
					elif p.get_type() == packet.PACKET_TYPE_NACK:
						logging.debug("Authentication failed...");
						self.sm.stalled();
						self.secure_socket.close();
						continue;
				else:
					logging.debug("invalid authentication packet...")
					self.sm.stalled();
					self.secure_socket.close();
					continue;
			elif self.sm.is_authenticated():
				buf = bytearray(self.secure_socket.recv(self.buffer_size));
				if len(buf) > 0:
					p = packet.ConfigurationPacket(buf);
					if p.get_type() != packet.PACKET_TYPE_CONFIGURATION:
						self.sm.stalled();
						logging.debug("Got invalid configuration packet...")
						self.secure_socket.close();
						continue;
					logging.debug("Got configuration packet...")
					if (utils.Utils.check_buffer_is_empty(p.get_ipv4_address()) or
						utils.Utils.check_buffer_is_empty(p.get_netmask()) or
						utils.Utils.check_buffer_is_empty(p.get_mtu())):
						logging.debug("Invalid configuration");
						self.sm.stalled();
						self.secure_socket.close();
						continue;
					self.tun = tun.Tun(config["TUN_NAME"],
						bytearray(p.get_ipv4_address()).decode(encoding="ASCII"),
						bytearray(p.get_netmask()).decode(encoding="ASCII"),
						struct.unpack("I", bytearray(p.get_mtu()))[0]);
					self.tun_mtu = struct.unpack("I", bytearray(p.get_mtu()))[0];
					self.routing_.configure_default_route(bytearray(p.get_ipv4_address()).decode(encoding="ASCII"));
					self.routing_.configure_tunnel_route(self.server_ip, self.default_gw);
					self.dns_.configure_dns(self.dns_server);
					self.nat_.enable_forwarding();
					self.nat_.masquerade_tun_interface();
					self.sm.configured();
				else:
					logging.debug("Empty buffer...")
					self.sm.stalled();
					self.secure_socket.close();
					continue;
			elif self.sm.is_configured():
				self.tun_thread = threading.Thread(target = self.tun_loop, daemon = True);
				self.tls_thread = threading.Thread(target = self.tls_loop, daemon = True);
				#self.tun_thread.daemon = True;
				#self.tls_thread.daemon = True;
				self.tun_thread.start();
				self.tls_thread.start();
				self.sm.running();
				logging.debug("Configured......")
			elif self.sm.is_running():
				if self.data_timeout < time():
					self.sm.stalled()
					logging.debug("TIMEOUT....")
				sleep(10);
				logging.debug("running periodic task....")
				print(self.sm.is_running())
			elif self.sm.is_stalled():
				logging.debug("Exiting the main loop")
				sleep(10)
				self.routing_.restore_default_route(self.default_gw);
				self.nat_.disable_masquerade_tun_interface();
				self.nat_.disable_forwarding();
				logging.debug("Exiting the main loop ....")
				break;

	def exit_handler(self):
		self.routing_.restore_default_route(self.default_gw);
		self.nat_.disable_masquerade_tun_interface();
		self.nat_.disable_forwarding();

# Start the client
from config import config
client = Client(config);

# Register exit hook
atexit.register(client.exit_handler);
thread_status = threading.Thread(target=client.status_loop);
thread_status.start()
client.loop();
logging.debug("Exiting the main loop....")
