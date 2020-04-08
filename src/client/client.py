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

# Timing
from time import sleep

class Client():
	def __init__(self, config):
		"""
		Secure socket and state machine initialization
		"""
		self.ctx = ssl.create_default_context();
		self.ctx.load_verify_locations(config["CA_CERTIFICATE"]);
		self.sock = socket.create_connection((config["SERVER_IP"], config["SERVER_PORT"]));
		self.ctx.check_hostname = True;
		self.secure_socket = self.ctx.wrap_socket(self.sock, server_hostname=config["SERVER_HOSTNAME"], server_side=False);
		self.sm = state.StateMachine();
		self.sm.connected();
		self.buffer_size = config["BUFFER_SIZE"];
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

	"""
	Reads data from secure socket
	"""
	def read_from_secure_socket(self):
		buf = bytearray(self.secure_socket.recv(self.buffer_size));
		if len(buf) == 0:
			raise Exception("Socket was closed");
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
		print("Starting to read from TLS socket...")
		while True:
			try:
				self.write_to_tun(self.read_from_secure_socket());
			except:
				print("Connection was closed, please restart the client...")
				#self.routing_.restore_default_route(self.default_gw);
				self.state.stalled();
				break;


	"""
	TLS loop
	"""
	def tls_loop(self):
		print("Starting to read from tun device....")
		while True:
			try:
				self.write_to_secure_socket(self.read_from_tun());
			except:
				print("Connection was closed, please restart the client...");
				#self.routing_.restore_default_route(self.default_gw);
				self.state.stalled();
				break;

	"""
	Client's main loop
	"""
	def loop(self):
		while True:
			if self.sm.is_unknown():
				continue;
			elif self.sm.is_connected():
				print("Sending authentication data...");
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
						print("Authentication succeeded...");
						self.sm.authenticated();
					elif p.get_type() == packet.PACKET_TYPE_NACK:
						print("Authentication failed...");
						return;
			elif self.sm.is_authenticated():
				buf = bytearray(self.secure_socket.recv(self.buffer_size));
				if len(buf) > 0:
					p = packet.ConfigurationPacket(buf);
					if p.get_type() != packet.PACKET_TYPE_CONFIGURATION:
						continue;
					print("Got configuration packet...")
					if (utils.Utils.check_buffer_is_empty(p.get_ipv4_address()) or 
						utils.Utils.check_buffer_is_empty(p.get_netmask()) or 
						utils.Utils.check_buffer_is_empty(p.get_mtu())):
						print("Invalid configuration");
						break;
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
			elif self.sm.is_configured():
				self.tun_thread = threading.Thread(target = self.tun_loop);
				self.tls_thread = threading.Thread(target = self.tls_loop);
				self.tun_thread.daemon = True;
				self.tls_thread.daemon = True;
				self.tun_thread.start();
				self.tls_thread.start();
				self.sm.running();
			elif self.sm.is_running():
				sleep(10);
			elif self.is_stalled():
				self.routing_.restore_default_route(self.default_gw);
				self.nat_.disable_masquerade_tun_interface();
				self.nat_.disable_forwarding();

	def exit_handler(self):
		self.routing_.restore_default_route(self.default_gw);
		self.nat_.disable_masquerade_tun_interface();
		self.nat_.disable_forwarding();

# Start the client
from config import config
client = Client(config);

# Register exit hook
atexit.register(client.exit_handler);
client.loop();
