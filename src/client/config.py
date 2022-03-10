config = {
	"SERVER_IP": "94.237.31.77", # Optional, if SERVER_HOSTNAME is registered in the DNS, this should be the IP address of proxy server if it is used
	"SERVER_PORT": 443, # This should be the port number of a proxy server if it is used
	"USERNAME": "dmitriy",
	"PASSWORD": "test",
	"TUN_NAME": "tun1",
	"SERVER_HOSTNAME": "strangebit.io",
	"CA_CERTIFICATE": "./certificates/certchain.pem", #Optional, if trusted certificates are used
	"BUFFER_SIZE": 1500,
	"DEFAULT_GW": "10.0.2.2", # Optional, now default gateway is obtained from /proc/route file
	"DNS_SERVER": "8.8.8.8",
	"USE_PROXY": True,
	"PROXY_PASSWORD": "test",
	"PROXY_TARGET_HOST": "strangebit.io",
	"PROXY_TARGET_PORT": 443
}
