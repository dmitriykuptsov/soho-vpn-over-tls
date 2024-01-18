#!/bin/bash

mkdir /opt/vpn/
rsync -rv src/* /opt/vpn/
sudo rsync -rv system.d/vpn-server.service /etc/systemd/system
sudo systemctl enable vvpn-server
sudo systemctl daemon-reload


