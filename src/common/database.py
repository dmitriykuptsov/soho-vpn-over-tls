# Security functions
from hashlib import sha256
# HEX stuff
from binascii import hexlify

class Database():
	def __init__(self):
		pass
	def is_authentic(self, username, password, salt):
		return True;

class FileDatabase(Database):

	@staticmethod
	def load_database(file):
		contents = None;
		with open(file) as f:
			contents = f.readlines();
		records = dict();
		for line in contents:
			record = line.split(" ");
			records[record[0]] = record[1].strip();
		return records;

	def __init__(self, file):
		super().__init__();
		self.records = FileDatabase.load_database(file);
	
	def is_authentic(self, username, password, salt):
		if not username or not password:
			return False;
		if not isinstance(password, bytearray) and not isinstance(password, bytes):
			return False;
		hash = sha256();
		salted_password = ''.join([chr(c) for c in bytearray(password)]) + salt;
		hash.update(salted_password.encode('ascii'));
		return self.records[''.join([chr(c) for c in bytearray(username)])] == hexlify(hash.digest()).decode("ascii");
