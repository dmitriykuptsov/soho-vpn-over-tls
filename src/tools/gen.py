# Cryptographic hash function
from hashlib import sha256

# binascii tools
from binascii import hexlify

# Command line arguments
from sys import argv

# Add current directory to Python path
import sys
import os
sys.path.append(os.getcwd())

# Server's config file
from server import config

def print_help():
	print("<<<Password generation tool>>>");
	print("Usage:");
	print("python3 tools/gen.py <password>");

if len(argv) != 2:
	print_help()
	exit();


def generate_hashed_password(password, salt):
	hash = sha256();
	salted_password = password + salt;
	hash.update(salted_password.encode('ascii'));
	return hexlify(hash.digest());

password = argv[1];
salt = config.config["SALT"];

print(generate_hashed_password(password, salt));