# VPN over TLS 

VPN over TLS is a project with one main purpose - allow VPN connections in countries with strict 
security policies. For example, we have seen that in some countries OpenVPN and SSH traffic is not
allowed. This puts certain limitations on the Internet usage. By deploying the VPN over TLS solution
on your custom cloud server makes it extremely hard for security personnel to track your connections.
Most importantly the traffic that you will be sending looks like normal HTTPS,

# Installation

We assume that both server and client are running Ubuntu 18.04 operating system.

First of all install python3, pip3 and needed libraries on both client and server machines.
To install the python3, run the following command on both server and client:

```
$ sudo apt-get install python3
```

Next install pip3 package manager using the following command:

```
$ sudo apt-get install python3-pip
```

Once the python3 installed, install required dependencies:

```
$ sudo pip3 install python-pytun
```

Next make sure you have git software installed:

```
$ sudo apt-get install git
```

Now everything is ready for the deployment of the VPN software: make a workspace directory somewhere on
your hard drive and checkout the project's repository (we need to do so on both client and server machine as 
usual):

```
$ git clone https://github.com/dmitriykuptsov/vpn_over_tls.git
```
# Configuration

If needed, on server machine go to the directory vpn_over_tls/src/server and modify the 
IP address of the tun interface in config.py file (currently it is set to 10.0.0.1, you may leave it as it is
if there is no conflict with your local IP address).

On client machine, also go to directory vpn_over_tls/src/client and modify the IP address the server in the config.py
file (currently it is 94.237.31.77, but you have to change it to an IP address of your own server (on server machine you 
can check the IP address either from administrative page, like it is offered in UpCloud or DigitalOcean, or by issuing ifconfig command))

One, probably, needs to also modify the IP address of default gateway. Currently it is set to 10.0.2.2, but it needs to be 
the default route of your network.

Finally, you need to generate password for your user. To do so, do the following (replace the user test password with your own password):
```
$ cd vpt_over_ssl/src
$ python3 tools/gen.py test
```

Then, copy the generated hash string and add it to the database.dat file in the vpn_over_ssl/server/ folder (you might also want to change the default username in that database file).

# Running the VPN

On server machine, go to directory vpn_over_tls/src and run the following command:

```
$ sudo python3 server/server.py
```

On client machine, go to directory vpn_over_tls/src and run the following command:

```
$ sudo python3 client/client.py
```

# Manual configuration

Newer version of VPN software automatically performs configuration of the client and server machines. However,
if for some reason the user needs to manually configure, he or she can follow the instructions presented below.

Open new terminal windows on both client and server (leave previous two windows open so that the VPN software will be running).

On server machine, execute the following commands in the console:

(i) Enable forwarding between the interfaces

```
$ sudo sysctl -w net.ipv4.ip_forward=1
```

(ii) Enable NAT in iptables

```
$ sudo iptables -t nat -A POSTROUTING ! -o lo -j MASQUERADE
```

On client machine, execute the following commands:

(i) Delete default route 

```
$ sudo ip route del default via 10.0.2.2
```

You will need to change IP address 10.0.2.2 with IP address of your default gateway!

(ii) Add route for tunnel 

```
$ sudo ip route add 94.237.31.77 via 10.0.2.2
```

You will neede to substitute 94.237.31.77 with IP address of your VPN server, and also change 10.0.2.2
with IP address of your default gateway!

(iii) Route all traffic through the tun interface

```
$ sudo ip route add default via 10.0.0.2
```

(iv) Change default DNS to, for example, 8.8.8.8. Do not use DNS offered by your DHCP, because it will not be reachable.
To modify the DNS modify the /etc/resolv.conf file.

# Testing the VPN

Now you should have VPN up and running. Lets make few tests.

(i) Lets ping directly VPN server:

```
$ ping 10.0.0.1
```

(ii) Test TCP connection to one of the Yandex webservers:
```
$ nc -vv ya.ru 443
```

(iii) And finally you can open your web browser, type ya.ru, for example, and 
check your IP address - it should be the IP address of the VPN server if 
everything was configured correctly.
