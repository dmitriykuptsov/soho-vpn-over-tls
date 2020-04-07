from pytun import TunTapDevice
from time import sleep

PSEUDO_HEADER_SIZE = 0x4;

class Tun():
	"""
	Initializes the tun device
	"""
	def __init__(self, name, address, netmask, mtu):
		self.name = name;
		self.tun = TunTapDevice(self.name);
		self.tun.addr = address
		self.tun.netmask = netmask
		self.tun.mtu = mtu
		self.tun.up();

	"""
	Reads data from device
	"""
	def read(self, nbytes):
		return self.tun.read(nbytes + PSEUDO_HEADER_SIZE);

	"""
	Writes buffer to device
	"""
	def write(self, buf):
		return self.tun.write(buf);

"""
tun = Tun('tun0', '10.0.1.1', '255.255.255.0', 1500);
while True:
	tun.read(1000);
	sleep(1);
"""
