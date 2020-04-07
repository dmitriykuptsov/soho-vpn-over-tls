#!/bin/bash

for i in {1..50}
do
	echo "Doing experiment number $i";
	iperf -c $1 -p 443
done
