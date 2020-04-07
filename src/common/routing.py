from os import system

"""
Routing utilities
"""
class Routing():
	def __init__(self):
		pass

	"""
	Configure default routes
	"""
	def configure_default_route(self, default_gw):
		system("ip route del default");
		system("ip route add default via %s" % (default_gw));

	"""
	Configure tunnel routes
	"""
	def configure_tunnel_route(self, server_ip, default_gw):
		system("ip route add %s via %s" % (server_ip, default_gw));

	"""
	Restores default route
	"""
	def restore_default_route(self, default_gw):
		system("ip route del default");
		system("ip route add default via %s" % (default_gw));

# On server:
# (i) enable forwarding between the interfaces
# sysctl -w net.ipv4.ip_forward=1
# (ii) enable NAT in iptables
# iptables -t nat -A POSTROUTING ! -o lo -j MASQUERADE
# On client
# 
# (i) delete default route 
# sudo ip route del default via 10.0.2.2
# (ii) add route for tunnel 
# sudo ip route add 94.237.31.77 via 10.0.2.2
# (iii) route all traffic through the tun interface
# sudo ip route add default via 10.0.0.2
# (iv) Change default DNS to 8.8.8.8 for example