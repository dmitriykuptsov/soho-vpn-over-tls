#!/bin/bash

from sys import argv
#print(argv)
fh = open(argv[1]);
lines = fh.readlines();
for line in lines:
	col = line.split(" ")
	if col[1] == "Kbits/sec\n":
		print(col[0])
	else:
		print(float(col[0])*1024)
