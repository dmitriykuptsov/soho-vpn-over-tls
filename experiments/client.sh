#!/bin/bash

for i in {1..50}
do
	echo "Doing experiment number $i";
	#iperf -c $1 -p 443
	#iperf -c $1 -p 80
	time wget https://mirrors.edge.kernel.org/pub/linux/kernel/v1.0/linux-1.0.tar.gz 2>/dev/null 
	rm linux-1.0.tar.gz
done
