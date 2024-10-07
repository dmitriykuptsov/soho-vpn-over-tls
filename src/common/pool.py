import sys
import os
sys.path.append(os.getcwd())

from common import utils

from math import log

class IpPool():
	def __init__(self, gateway_ip, netmask):
		self.counter = 1;
		self.max_hosts = int(log(utils.Utils.ip_to_int("255.255.255.255") ^ utils.Utils.ip_to_int(netmask), 2)) - 2;
		self.network_part = utils.Utils.ip_to_int(gateway_ip) & utils.Utils.ip_to_int(netmask);
		if (utils.Utils.ip_to_int("255.255.255.255") ^ utils.Utils.ip_to_int(netmask)) == 0x0:
			raise Exception("Netmask cannot be 255.255.255.255");
		self.pool = [gateway_ip];

	def lease_ip(self):
		self.counter = 1;
		next_ip = self.network_part + self.counter;
		while self.counter <= self.max_hosts:
			self.counter += 1;
			if not utils.Utils.int_to_ip(next_ip) in self.pool:
				self.pool.append(utils.Utils.int_to_ip(next_ip));
				return utils.Utils.int_to_ip(next_ip);
			next_ip = self.network_part + self.counter;
		return None;

	def release_ip(self, ip):
		self.counter = 1;
		if ip in self.pool:
			self.pool.remove(ip);


"""
pool = IpPool("192.168.0.1", "255.255.255.0");
print(pool.lease_ip())
print(pool.lease_ip())
print(pool.lease_ip())
"""
