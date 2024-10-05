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
__copyright__ = "Copyright 2020, stangebit"
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

# Structures
import struct

# Common helpers
from common import packet
from common import database
from common import state
from common import pool
from common import tun
from common import utils
from common import tun
from common import dns
from common import routing
from common import nat

# Threading
import threading

# Configuration
import config
# Security functions
from hashlib import sha256

# Timing 
from time import sleep, time

# Exit hook
import atexit

class Server():

	"""
	Initializes the server
	"""
	def __init__(self, config, database):
		"""
		Initialize the database
		"""
		self.database = database;

		"""
		Initialize state machine
		"""
		self.sm = state.StateMachine();

		"""
		Initialize IP address pool
		"""

		self.ip_pool = pool.IpPool(config["TUN_ADDRESS"], config["TUN_NETMASK"]);

		"""
		Server configuration 
		"""

		self.hostname = config["LISTEN_ADDRESS"];
		self.port = config["LISTEN_PORT"];
		self.tun_address = config["TUN_ADDRESS"];
		self.tun_name = config["TUN_NAME"];
		self.tun_netmask = config["TUN_NETMASK"];
		self.tun_mtu = config["TUN_MTU"];
		self.buffer_size = config["BUFFER_SIZE"];
		self.salt = config["SALT"];

		self.data_timeout = time() + config["DATA_TIMEOUT"];

		"""
		Create secure socket and bind it to address and port
		"""

		self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2);
		self.ctx.load_cert_chain(config["CERTIFICATE_CHAIN"], config["PRIVATE_KEY"]);
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0);
		self.sock.bind((self.hostname, self.port));
		self.sock.listen(5);
		self.sock.settimeout(10);
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
		self.secure_sock = self.ctx.wrap_socket(self.sock, server_side=True);

		"""
		Create tun interface
		"""
		self.tun = tun.Tun(self.tun_name, self.tun_address, self.tun_netmask, self.tun_mtu);

		"""
		Configure NATing
		"""
		self.nat_ = nat.NAT();
		self.nat_.enable_forwarding();
		self.nat_.masquerade_tun_interface();
		"""
		Initialize secure socket buffer
		"""
		self.secure_socket_buffer = [];

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
		userdata = packet.DataPacket();
		userdata.set_payload(payload);
		try:
			self.client_socket.send(userdata.get_buffer());
		except:
			os.system("ss --tcp state CLOSE-WAIT --kill")
			raise Exception("Socket was closed");

	"""
	Reads data from secure socket
	"""
	def read_from_secure_socket(self):
		buf = self.client_socket.recv(self.buffer_size);
		self.data_timeout = time() + config["DATA_TIMEOUT"];
		if len(buf) == 0:
			raise Exception("Socket was closed");
		self.secure_socket_buffer += buf;
		if len(self.secure_socket_buffer) <= packet.Packet.get_header_length():
			return None;
		packet_length = packet.Packet.get_total_length(self.secure_socket_buffer);
		if packet_length > len(self.secure_socket_buffer):
			return None;
		buf = self.secure_socket_buffer[:packet_length];
		self.secure_socket_buffer = self.secure_socket_buffer[packet_length:];
		userdata = packet.DataPacket(buf);
		if userdata.get_type() != packet.PACKET_TYPE_DATA:
			return None;
		return userdata.get_payload();

	"""
	Reads data from TUN interface
	"""
	def read_from_tun(self):
		buf = self.tun.read(self.tun_mtu);
		return buf;
	
	"""
	TUN read loop
	"""

	def tun_loop(self):
		while True:
			try:
				self.write_to_tun(self.read_from_secure_socket());
			except:
				print("Connection was closed TUN loop");
				self.sm.unknown();
				self.ip_pool.release_ip(self.client_ip);
				self.client_socket.close();
				os.system("ss --tcp state CLOSE-WAIT --kill")
				#self.tun_thread.join();
				break;

	"""
	TLS loop
	"""
	def tls_loop(self):
		while True:
			try:
				self.write_to_secure_socket(self.read_from_tun());
			except:
				print("Connection was closed TLS loop")
				self.sm.unknown();
				self.ip_pool.release_ip(self.client_ip);
				self.client_socket.close();
				os.system("ss --tcp state CLOSE-WAIT --kill")
				break;
	"""
	Main loop
	"""
	def loop(self):
		while True:
			if self.sm.is_unknown():
				try:
					(sock, addr) = self.secure_sock.accept();
					#sock.settimeout(30)
					self.client_socket = sock;
					self.client_address = addr;
					print("Got connection from %s" % (self.client_address[0]));
					self.sm.connected();
				except:
					print("Could not open the socket...")
					sleep(1);
					continue;
			elif self.sm.is_connected():
				buf = None
				try:
					buf = bytearray(self.client_socket.recv(self.buffer_size));
					if len(buf) == 0:
						raise Exception("Socket was closed");
				except:
					print("Failed to read from socket...");
					self.client_socket.close();
					self.sm.unknown();
					continue;
				
				print("Received authentication packet...");
				p = packet.AuthenticationPacket(buf);
				try:
					if p.get_type() != packet.PACKET_TYPE_AUTHENTICATION:
						self.client_socket.close();
						self.sm.unknown();
						continue;
					if utils.Utils.check_buffer_is_empty(p.get_password()):
						print("Invalid credentials");
						try:
							nack = packet.NegativeAcknowledgementPacket();
							self.client_socket.send(nack.get_buffer());
							#self.client_socket.close();
						except:
							print("Failed to write into socket...");
						self.client_socket.close();
						self.sm.unknown();
						continue;
					if utils.Utils.check_buffer_is_empty(p.get_username()):
						print("Invalid credentials");
						try:
							nack = packet.NegativeAcknowledgementPacket();
							self.client_socket.send(nack.get_buffer());
							#self.client_socket.close();
						except:
							print("Failed to write into socket...");
						self.client_socket.close();
						self.sm.unknown();
						continue;
					if self.database.is_authentic(p.get_username(), p.get_password(), self.salt):
						self.sm.authenticated();
						try:
							ack = packet.AcknowledgementPacket();
							self.client_socket.send(ack.get_buffer());
						except:
							print("Failed to write data into socket...");
							self.client_socket.close();
							self.sm.unknown();
					else:
						try:
							nack = packet.NegativeAcknowledgementPacket();
							self.client_socket.send(nack.get_buffer());
							#self.client_socket.close();
							#self.sm.unknown();
						except:
							print("Failed to write into socket...");
						print("Invalid credentials were used");
						self.client_socket.close();
						self.sm.unknown();
				except:
					self.client_socket.close();
					self.sm.unknown();
					print("Could not parse data");
			elif self.sm.is_authenticated():
				print("Sending configuration data to the VPN client")
				self.client_ip = self.ip_pool.lease_ip();
				configuration = packet.ConfigurationPacket();
				configuration.set_netmask(list(bytearray(self.tun_netmask, encoding="ASCII")));
				configuration.set_default_gw(list(bytearray(self.tun_address, encoding="ASCII")));
				configuration.set_ipv4_address(list(bytearray(self.client_ip, encoding="ASCII")));
				configuration.set_mtu(list(struct.pack("I", self.tun_mtu)));
				try:
					self.client_socket.send(configuration.get_buffer());
					self.sm.configured();
				except:
					self.sm.unknown();
					self.client_socket.close();
					print("Failed to write into socket...");
			elif self.sm.is_configured():
				self.tun_thread = threading.Thread(target = self.tun_loop);
				self.tls_thread = threading.Thread(target = self.tls_loop);
				self.maintenance_thread = threading.Thread(target = self.maintenance_loop)
				self.tun_thread.daemon = True;
				self.tls_thread.daemon = True;
				self.maintenance_thread.daemon = True;
				self.tun_thread.start();
				self.tls_thread.start();
				self.maintenance_thread.start();
				self.sm.running();
			elif self.sm.is_running():
				if self.data_timeout <= time():
					self.sm.unknown()
					self.client_socket.close()
					print("Connection was stalled in running state....")
				sleep(10);

	def exit_handler(self):
		self.nat_.disable_forwarding();
		self.nat_.disable_masquerade_tun_interface();

	def maintenance_loop(self):
		timeout = time() + 30 * 1000
		while True:
			if self.sm.is_connected():
				if time() > timeout:
					#timeout = time() + 30 * 1000
					self.client_socket.close()
					self.sm.unknown()
					print("Connection timed out")
					os.system("ss --tcp state CLOSE-WAIT --kill")
					break;
			elif self.sm.is_unknown():
				timeout = time() + 30 * 1000
			sleep(1)

# Start the server
from config import config
server = Server(config, database.FileDatabase("./server/database.dat"));
atexit.register(server.exit_handler);
server.loop();
