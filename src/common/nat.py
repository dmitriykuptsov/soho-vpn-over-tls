from os import system


"""
Network address translation class
"""
class NAT():
	def __init__(self):
		pass

	"""
	Enable forwarding on all interfaces
	"""
	def enable_forwarding(self):
		system("sysctl -w net.ipv4.ip_forward=1");

	"""
	Enable network address translation on all interfaces
	"""
	def masquerade_tun_interface(self):
		system("iptables -t nat -A POSTROUTING ! -o lo -j MASQUERADE");

	"""
	Disable forwarding on all interfaces. 
	After this command packets cannot be forwarded
	between the interfaces.
	"""
	def disable_forwarding(self):
		system("sysctl -w net.ipv4.ip_forward=0");

	"""
	Disable address translation on all interfaces.
	Note, if previously the command was called serveral
	times, this will remove only latest insert into IP tables.
	"""
	def disable_masquerade_tun_interface(self):
		system("iptables -t nat -D POSTROUTING ! -o lo -j MASQUERADE");