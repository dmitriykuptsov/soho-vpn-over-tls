from os import system

"""
DNS configuration 
"""
class DNS():
	"""
	Default constructor
	"""
	def __init__(self):
		pass

	"""
	Configures DNS
	"""
	def configure_dns(self, dns_server):
		system("echo nameserver %s > /etc/resolv.conf" % (dns_server));