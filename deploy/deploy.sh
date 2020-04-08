#!/bin/bash

mkdir /opt/vpn/
rsync -rv src/* /opt/vpn/
sudo rsync -rv system.d/vpn.service /etc/systemd/system
sudo systemctl enable vpn
sudo systemctl daemon-reload

