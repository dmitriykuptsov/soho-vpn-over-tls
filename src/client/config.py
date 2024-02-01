config = {
	"SERVER_IP": "94.237.31.77", # Optional, if SERVER_HOSTNAME is registered in the DNS
	"SERVER_PORT": 443,
	"USERNAME": "dmitriy",
	"PASSWORD": "test",
	"TUN_NAME": "tun1",
	"SERVER_HOSTNAME": "strangebit.com",
	"CA_CERTIFICATE": "./certificates/certchain.pem", #Optional, if trusted certificates are used
	"BUFFER_SIZE": 1500,
	"DEFAULT_GW": "10.0.2.2", # Optional, now default gateway is obtained from /proc/route file
	"DNS_SERVER": "8.8.8.8",
    "DATA_TIMEOUT": 10*60*1000
}
