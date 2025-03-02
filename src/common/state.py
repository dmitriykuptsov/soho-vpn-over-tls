VPN_TLS_STATE_UNKONWN                = 0x1;
VPN_TLS_STATE_CONNECTED              = 0x2;
VPN_TLS_STATE_WAITING_AUTHENTICATION = 0x3;
VPN_TLS_STATE_AUTHENTICATED          = 0x4;
VPN_TLS_STATE_CONFIGURED             = 0x5;
VPN_TLS_STATE_RUNNING                = 0x6;
VPN_TLS_STATE_STALLED                = 0x7;

"""
VPN over TLS state
"""
class State():

	"""
	Initializes the state
	"""
	def __init__(self):
		self.state = VPN_TLS_STATE_UNKONWN;

	"""
	Returns current state of connection
	"""
	def get_state(self):
		return self.state;

	def set_state(self, state = VPN_TLS_STATE_UNKONWN):
		self.state = state;


"""
State machine
"""
class StateMachine():
	def __init__(self):
		self.state = State();

	"""
	Checks if the state is unkown
	"""
	def is_unknown(self):
		return self.state.get_state() == VPN_TLS_STATE_UNKONWN;

	"""
	Checks if the state is connected
	"""
	def is_connected(self):
		return self.state.get_state() == VPN_TLS_STATE_CONNECTED;

	"""
	Checks if the state is authenticated
	"""
	def is_authenticated(self):
		return self.state.get_state() == VPN_TLS_STATE_AUTHENTICATED;

	"""
	Checks if wether we are waiting for authentication result
	"""
	def is_waiting_for_authentication(self):
		return self.state.get_state() == VPN_TLS_STATE_WAITING_AUTHENTICATION;

	"""
	Checks if the state is configured
	"""
	def is_configured(self):
		return self.state.get_state() == VPN_TLS_STATE_CONFIGURED;

	"""
	Checks if the state is running
	"""
	def is_running(self):
		return self.state.get_state() == VPN_TLS_STATE_RUNNING;

	def is_stalled(self):
		return self.state.get_state() == VPN_TLS_STATE_STALLED;

	def unknown(self):
		self.state.set_state(VPN_TLS_STATE_UNKONWN);

	"""
	Transition the state to connected
	"""
	def connected(self):
		self.state.set_state(VPN_TLS_STATE_CONNECTED);

	"""
	Waiting for authentication to complete
	"""
	def waiting_for_authentication(self):
		self.state.set_state(VPN_TLS_STATE_WAITING_AUTHENTICATION);

	"""
	Transition the state to authenticated
	"""
	def authenticated(self):
		self.state.set_state(VPN_TLS_STATE_AUTHENTICATED);

	"""
	Transition the state to configured
	"""
	def configured(self):
		self.state.set_state(VPN_TLS_STATE_CONFIGURED);

	"""
	Transition the state to running
	"""
	def running(self):
		self.state.set_state(VPN_TLS_STATE_RUNNING);

	def stalled(self):
		self.state.set_state(VPN_TLS_STATE_STALLED);

	def __str__(self):
		return str(self.state.get_state())