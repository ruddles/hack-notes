# Basic syntax
`john [options] [path-to-file]`

John will attempt to figure out what it's cracking if you don't specify it

`john --wordlist[path-to-wordlist] [path-to-file]`

# Identifying hashes
If you want to be more specific you can use https://hashes.com/en/tools/hash_identifier or the `hash-identifier` command https://gitlab.com/kalilinux/packages/hash-identifier/-/tree/kali/master to figure it out.

e.g.
`wget https://gitlab.com/kalilinux/packages/hash-identifier/-/raw/kali/master/hash-id.py` then `python3 hash-id.py`

## Specify format
`john --format=[format] --wordlist=[path-to-wordlist] [path-to-file]`
list formats with
`john --list=formats`

example for md5
`~/code/john/run/john --format=raw-md5 --wordlist=/home/rob/rockyou.txt ./first_task_hashes/hash2.txt`

# Cracking Windows Auth Hashes
NThash is the hash format used by modern windows OS.  These can be dumped by tools like mimikatz or extracted from NTDS.dlt.

`~/code/john/run/john --format=nt --wordlist=/home/rob/rockyou.txt ./ntlm.txt`

# Cracking /etc/shadow
This is the file in linux where passwords are stored

You need both /etc/shadow and /etc/passwd to get a format the john understands, then

`unshadow [path-to-passwd] [path-to-shadow] > unshadowed.txt`

`~/code/john/run/john --format=sha512crypt --wordlist=/home/rob/rockyou.txt ./etchashes.txt`

# Single Crack Mode
This mode doesn't take a wordlist, instead it uses the username provided and slightly changes the letters and numbers.  John can understand GECOS (values separated by : like in /etc/shadows)

`john --single --format=raw-md5 hash7.txt`

You can specify custom rules in /etc/john/john.conf - this can be found in the wiki https://www.openwall.com/john/doc/RULES.shtml and then run with `--rule[rule-name]`
e.g. `cAz"[0-9][!£$%@]"`
c = capitalize
Az = append the rest of the word
[0-9] = append a number between 0-9
[!£$%@] = append a symbol

so this would turn password into Password1!

There's already a large set of rule (if you've installed jumbo john via git or using kali)

# Cracking Zip Files
we can use `zip2john` to create a hash file we can then pipe into john

`~/code/john/run/zip2john ./secure.zip > secure.hash`
`~/code/john/run/john --wordlist=/home/rob/rockyou.txt secure.hash`

# Cracking Rar Files
we can use `rar2jon` to create the hash
`~/code/john/run/rar2john secure.rar > securerar.hash`
`~/code/john/run/john --wordlist=/home/rob/rockyou.txt securerar.hash`

# Cracking SSH
if we have a password protected id_rsa file we can use `ssh2john`
`python3 ~/code/john/run/ssh2john.py ./idrsa.id_rsa > id_rsa.hash`
`~/code/john/run/john --wordlist=/home/rob/rockyou.txt id_rsa.hash`