# SOHO VPN over TLS 

VPN over TLS is a project with one main purpose - allow VPN connections in countries with strict 
security policies. For example, we have seen that in some countries OpenVPN and SSH traffic is not
allowed. This puts certain limitations on the Internet usage. By deploying the VPN over TLS solution
on your custom cloud server makes it extremely hard for security personnel to track your connections.
Most importantly the traffic that you will be sending looks like normal HTTPS. This solution 
should be deployed on a SOHO VPN box.

# Installation

We assume that both server and client are running Ubuntu 18.04 operating system. NOTE!
The VPN client box SHOULD not be an element on the path. INSTEAD,
it SHOULD be a separate element inside the Intranet. Please, consider
the following setup:

```
+----------------+
| Network device |----+
+----------------+  Plain 
                   traffic
                      |         SOHO
+----------------+    |       +--------+               +----------+
| Network device |--+ |    +->| Router |---->Internet->|VPN server|
+----------------+  | |    |  +--------+               +----------+
                    | |   TLS
                    v v    |
                  +-----------------+
                  | VPN box(client) |
                  +-----------------+
```


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
$ git clone https://github.com/dmitriykuptsov/soho_vpn_over_tls.git
```

# Configuration

If needed, on server machine go to the directory vpn_over_tls/src/server and modify the 
IP address of the tun interface in config.py file (currently it is set to 10.0.0.1, you may leave it as it is
if there is no conflict with your local IP address).

On SOHO box also go to directory vpn_over_tls/src/client and modify the IP address the server in the config.py
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

Finally, it is probably needed to set TCP keepalive, so that connections will be long living:

https://blog.voina.org/tcp-keepalive-what-is-it-why-do-you-need-it-how-to-configure-it-on-linux/

# Running the VPN

On server machine, go to directory vpn_over_tls/src and run the following command:

```
$ sudo python3 server/server.py
```

On SOHO box (we use Raspberry PI as such), go to directory vpn_over_tls/src and run the following command:

```
$ sudo python3 client/client.py
```

# Client configuration

On client machine (the machine you normally use to browse the Internet)
you need to modify the default gateway: Configure the default gateway
with the IP address of your SOHO VPN client box IP address and you should be all set:

```
$ sudo ip route del default
$ sudo ip route add default via <IP address of SOHO TLS VPN box>
```

# Testing the VPN

Now you should have VPN up and running. Now, lets make few tests.

Open your web browser, type ya.ru, for example, and 
check your IP address - it should be the IP address of the VPN server if 
everything was configured correctly.

# Future work

We have noticed that sometimes curious Internet users and port scanners
can check what is going on server. To solve the issue we can hide the 
service behind regular HTTP server. To open access we can use port knocking:
For example, we can make an Nginx running on port 443, configure it 
with the following location:

```
location ~ ^/secret/(.*) {
    proxy_set_header  X-Real-IP  $remote_addr;
    proxy_pass http://127.0.0.1:9090/$1;
  }
```

When the user knocks, the web application opens firewall access to the clinet:

```
iptables -t nat -A PREROUTING -p tcp -s <clients IP> --dport 443 -j REDIRECT --to-port 9000
```

Then a SOHO VPN client kicks in and establishes a connection to our VPN service and IP table rule 
is deleted. Otherwise the web server serves regular client some random page. This way operators 
will not be able to distinguish VPN server from normal Web server.
