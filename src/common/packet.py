# Packet lengths
PACKET_LENGTH_FIELD_LENGTH = 0x2;
PACKET_TYPE_FIELD_LENGTH   = 0x2;

PACKET_TYPE_FIELD_OFFSET   = 0x0;
PACKET_LENGTH_FIELD_OFFSET = 0x2;

# Offset for the attributes
PACKET_ATTR_OFFSET         = 0x4;

# Attrbute fields lengths and offsets
ATTR_TYPE_FIELD_LENGTH     = 0x1;
ATTR_LENGTH_FIELD_LENGTH   = 0x3;
ATTR_LENGTH_FIELD_OFFSET   = 0x1;
ATTR_VALUE_FIELD_OFFSET    = 0x4;

# Attribute types
ATTR_TYPE_PASSWORD         = 0x1;
ATTR_TYPE_USERNAME         = 0x2;
ATTR_TYPE_IPV4_ADDRESS     = 0x3;
ATTR_TYPE_DEFAULT_GATEWAY  = 0x4;
ATTR_TYPE_NETMASK          = 0x5;
ATTR_TYPE_MTU              = 0x6;
ATTR_TYPE_USERDATA         = 0x7;

# Packet types
PACKET_TYPE_AUTHENTICATION = 0x1;
PACKET_TYPE_CONFIGURATION  = 0x2;
PACKET_TYPE_DATA           = 0x3;
PACKET_TYPE_ACK            = 0x4;
PACKET_TYPE_NACK           = 0x5;
PACKET_TYPE_PING           = 0x6;
PACKET_TYPE_PONG           = 0x7;

# Import structures
import struct

"""
General packet 
"""
class Packet():
	"""
	Initializes the buffer
	"""
	def __init__(self, buf = None):
		if not buf:
			self.buf = [0] * (PACKET_LENGTH_FIELD_LENGTH + PACKET_TYPE_FIELD_LENGTH);
		else:
			self.buf = buf;

	"""
	Gets the buffer
	"""
	def get_buffer(self):
		return bytearray(self.buf);

	"""
	Sets packet type
	"""
	def set_type(self, type):
		self.buf[PACKET_TYPE_FIELD_OFFSET] = (type >> 8) & 0xFF;
		self.buf[PACKET_TYPE_FIELD_OFFSET + 1] = (type & 0xFF);

	"""
	Gets the type of the packet
	"""
	def get_type(self):
		return (
			((self.buf[PACKET_TYPE_FIELD_OFFSET] << 8)) +
			(self.buf[PACKET_TYPE_FIELD_OFFSET + 1] & 0xFF)
		);

	"""
	Sets length
	"""
	def set_length(self, length):
		self.buf[PACKET_LENGTH_FIELD_OFFSET] = (length >> 8) & 0xFF;
		self.buf[PACKET_LENGTH_FIELD_OFFSET + 1] = (length & 0xFF);

	"""
	Gets length
	"""
	def get_length(self):
		return (
			((self.buf[PACKET_LENGTH_FIELD_OFFSET] << 8)) +
			(self.buf[PACKET_LENGTH_FIELD_OFFSET + 1] & 0xFF)
		);

	"""
	Static method, which allows user to check the length of a packet
	"""
	@staticmethod
	def get_total_length(buf):
		return (((buf[PACKET_LENGTH_FIELD_OFFSET] << 8)) +
			(buf[PACKET_LENGTH_FIELD_OFFSET + 1] & 0xFF) + 
			PACKET_LENGTH_FIELD_LENGTH +
			PACKET_TYPE_FIELD_LENGTH
			);

	@staticmethod
	def get_header_length():
		return PACKET_LENGTH_FIELD_LENGTH + PACKET_TYPE_FIELD_LENGTH;

	"""
	Adds attribute to the packet
	"""
	def add_attribute(self, attr):
		length = self.get_length();
		offset = PACKET_ATTR_OFFSET + length;
		self.buf[offset:offset + len(attr.get_buffer())] = attr.get_buffer();
		self.set_length(length + len(attr.get_buffer()));

	"""
	Gets all attributes of the packet
	"""
	def get_attributes(self):
		attributes = [];
		length = self.get_length();
		attrs_buffer = self.buf[PACKET_ATTR_OFFSET:PACKET_ATTR_OFFSET + length];
		offset = 0;
		while offset < length:
			attr_length = (
				((attrs_buffer[offset + ATTR_LENGTH_FIELD_OFFSET] << 16)) +
				((attrs_buffer[offset + ATTR_LENGTH_FIELD_OFFSET + 1] << 8)) +
				((attrs_buffer[offset + ATTR_LENGTH_FIELD_OFFSET + 2]) & 0xFF)
				);
			attribute = Attribute(attrs_buffer[offset: offset + ATTR_LENGTH_FIELD_LENGTH + ATTR_TYPE_FIELD_LENGTH + attr_length]);
			attributes.append(attribute);
			offset += ATTR_LENGTH_FIELD_LENGTH + ATTR_TYPE_FIELD_LENGTH + attr_length;
		return attributes;

"""
VPN TLS attributes
"""
class Attribute():
	"""
	Initializes the attribute
	"""
	def __init__(self, buf = None):
		if not buf:
			self.buf = [0] * (ATTR_TYPE_FIELD_LENGTH + ATTR_LENGTH_FIELD_LENGTH);
		else:
			self.buf = buf;

	"""
	Sets the type of an attribute
	"""
	def set_type(self, type):
		self.buf[0] = type;

	"""
	Gets the type of an attribute
	"""
	def get_type(self):
		return self.buf[0];

	"""
	Sets the length of an attribute.
	Indeed this should be no more than 2 bytes
	because packet length is just two bytes.
	"""
	def set_length(self, length):
		self.buf[ATTR_LENGTH_FIELD_OFFSET] = (length >> 16) & 0xFF;
		self.buf[ATTR_LENGTH_FIELD_OFFSET + 1] = (length >> 8) & 0xFF;
		self.buf[ATTR_LENGTH_FIELD_OFFSET + 2] = (length & 0xFF);

	"""
	Gets the length of an attribute
	"""
	def get_length(self):
		return (
			(self.buf[ATTR_LENGTH_FIELD_OFFSET + 0] << 16) + 
			(self.buf[ATTR_LENGTH_FIELD_OFFSET + 1] << 8) + 
			(self.buf[ATTR_LENGTH_FIELD_OFFSET + 2])
			);

	"""
	Sets the value of an attrbiute
	"""
	def set_value(self, value):
		self.set_length(len(value));
		self.buf[ATTR_VALUE_FIELD_OFFSET:ATTR_VALUE_FIELD_OFFSET + len(value)] = value;


	"""
	Gets the value of an attribute
	"""
	def get_value(self):
		length = self.get_length();
		return self.buf[ATTR_VALUE_FIELD_OFFSET:ATTR_VALUE_FIELD_OFFSET + length];

	"""
	Returns the buffer value
	"""
	def get_buffer(self):
		return self.buf;

class AcknowledgementPacket(Packet):
	"""
	Initializes the buffer
	"""
	def __init__(self, buf = None):
		super().__init__(buf);
		self.set_type(PACKET_TYPE_ACK);

class NegativeAcknowledgementPacket(Packet):
	"""
	Initializes the buffer
	"""
	def __init__(self, buf = None):
		super().__init__(buf);
		self.set_type(PACKET_TYPE_NACK);

class AuthenticationPacket(Packet):
	"""
	Initializes the buffer
	"""
	def __init__(self, buf = None):
		super().__init__(buf);
		self.set_type(PACKET_TYPE_AUTHENTICATION);

	"""
	Sets the password
	"""
	def set_password(self, buf):
		pass_attribute = Attribute();
		pass_attribute.set_value(buf);
		pass_attribute.set_type(ATTR_TYPE_PASSWORD);
		self.add_attribute(pass_attribute);

	""" 
	Sets the username
	"""
	def set_username(self, buf):
		username_attribute = Attribute();
		username_attribute.set_value(buf);
		username_attribute.set_type(ATTR_TYPE_USERNAME);
		self.add_attribute(username_attribute);
		
	"""
	Gets the username
	"""
	def get_username(self):
		attributes = self.get_attributes();
		for attribute in attributes:
			if attribute.get_type() == ATTR_TYPE_USERNAME:
				return attribute.get_value();
		return None;

	"""
	Gets the password
	"""
	def get_password(self):
		attributes = self.get_attributes();
		for attribute in attributes:
			if attribute.get_type() == ATTR_TYPE_PASSWORD:
				return attribute.get_value();
		return None;
"""
Configuration packet
"""
class ConfigurationPacket(Packet):
	"""
	Initializes the buffer
	"""
	def __init__(self, buf = None):
		super().__init__(buf);
		self.set_type(PACKET_TYPE_CONFIGURATION);

	"""
	Sets the netmask of the packet
	"""
	def set_netmask(self, buf):
		netmask_attribute = Attribute();
		netmask_attribute.set_value(buf);
		netmask_attribute.set_type(ATTR_TYPE_NETMASK);
		self.add_attribute(netmask_attribute);

	"""
	Gets the netmask
	"""
	def get_netmask(self):
		attributes = self.get_attributes();
		for attribute in attributes:
			if attribute.get_type() == ATTR_TYPE_NETMASK:
				return attribute.get_value();
		return None;

	"""
	Sets default gateway
	"""
	def set_default_gw(self, buf):
		default_gw_attribute = Attribute();
		default_gw_attribute.set_value(buf);
		default_gw_attribute.set_type(ATTR_TYPE_DEFAULT_GATEWAY);
		self.add_attribute(default_gw_attribute);

	"""
	Gets the default gateway
	"""
	def get_default_gw(self):
		attributes = self.get_attributes();
		for attribute in attributes:
			if attribute.get_type() == ATTR_TYPE_DEFAULT_GATEWAY:
				return attribute.get_value();
		return None;

	"""
	Sets MTU
	"""
	def set_mtu(self, buf):
		mtu_attribute = Attribute();
		mtu_attribute.set_value(buf);
		mtu_attribute.set_type(ATTR_TYPE_MTU);
		self.add_attribute(mtu_attribute);

	"""
	Gets MTU
	"""
	def get_mtu(self):
		attributes = self.get_attributes();
		for attribute in attributes:
			if attribute.get_type() == ATTR_TYPE_MTU:
				return attribute.get_value();
		return None;

	"""
	Sets IPv4 address
	"""
	def set_ipv4_address(self, buf):
		ipv4_attribute = Attribute();
		ipv4_attribute.set_value(buf);
		ipv4_attribute.set_type(ATTR_TYPE_IPV4_ADDRESS);
		self.add_attribute(ipv4_attribute);

	"""
	Gets IPv4 address
	"""
	def get_ipv4_address(self):
		attributes = self.get_attributes();
		for attribute in attributes:
			if attribute.get_type() == ATTR_TYPE_IPV4_ADDRESS:
				return attribute.get_value();
		return None;
"""
Data packet
"""
class DataPacket(Packet):
	"""
	Initializes the buffer
	"""
	def __init__(self, buf = None):
		super().__init__(buf);
		self.set_type(PACKET_TYPE_DATA);

	"""
	Sets the payload of a packet
	"""
	def set_payload(self, payload):
		payload_attr = Attribute();
		payload_attr.set_value(payload);
		payload_attr.set_type(ATTR_TYPE_USERDATA);
		self.add_attribute(payload_attr);

	"""
	Returns payload of a packet
	"""
	def get_payload(self):
		attributes = self.get_attributes();
		for attribute in attributes:
			if attribute.get_type() == ATTR_TYPE_USERDATA:
				return attribute.get_value();

class PingPacket(Packet):
	"""
	Initializes the buffer
	"""
	def __init__(self, buf = None):
		super().__init__(buf);
		self.set_type(PACKET_TYPE_PING);

class PongPacket(Packet):
	"""
	Initializes the buffer
	"""
	def __init__(self, buf = None):
		super().__init__(buf);
		self.set_type(PACKET_TYPE_PONG);

"""
auth = AuthenticationPacket();
auth.set_username("test");
auth.set_password("password");
print(''.join(auth.get_username()))
print(''.join(auth.get_password()))

configuration = ConfigurationPacket();
configuration.set_netmask("255.255.0.0");
configuration.set_default_gw("192.168.0.12");
configuration.set_ipv4_address("10.0.0.1");
print(''.join(configuration.get_default_ipv4()));
print(''.join(configuration.get_default_gw()));
print(''.join(configuration.get_netmask()));

userdata = DataPacket();
userdata.set_payload(bytearray("dasddadasdasdsadasdasdas", encoding="ASCII"));
print(userdata.get_payload());
"""
