#!/bin/bash

while true; do top -l 3 -o cpu -n 10 | grep "*[0-9]*.*" | awk -F" " '{print $2" "$3}' |  grep -e "^[a-zA-Z\s]*\s[0-9\.]*$" | grep -v "0.0" >> cpu.log; sleep 1; done
