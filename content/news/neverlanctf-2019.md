+++
categories = ["News", "CTF", "NeverlanCTF-2019"]
date = "2019-02-04"
title = "Neverlanctf 2019 - Recap"
thumbnail = "/img/neverlanctf/logo.jpg"
nopaging = "true"
draft = "false"
+++

The NeverLAN CTF is an online jeopardy style Capture the Flag created for student. This CTF is begineer friendly and overall easy. The 2019 edition ran from thursday, January 31st to sunday, February 3rd 2019. This event was created with the goal of teaching the younger generation about Computer Science and the value of critical thinking and problem solving.

The competition proposed several classic categories like web, reverse and crypto but also proposed originals categories like cloud, bash and trivia questions.

![](/img/neverlanctf/all-challenges-1.png)
![](/img/neverlanctf/all-challenges-2.png)

I finished the competition with the 46th place on the global scoreboard and with the 13th place on the student scoreboard.

![](/img/neverlanctf/scoreboard.png)
![](/img/neverlanctf/student-scoreboard.png)


So what did we learn from this competition ?

## Cloud : AWS and Google Cloud

The cloud category was (for me), the most interesting part of this competition.

#### Concept of AWS bucket

https://en.wikipedia.org/wiki/Amazon_S3


#### Detect an AWS bucket

```
dig website.cloud           # With Dig
nslookup website.cloud      # With Nslookup
```


#### Use AWS CLI

```bash
pip install awscli --upgrade --user
aws s3
```

#### List content of a public AWS bucket

```
aws s3 ls s3://website.cloud --no-sign-request --region us-west-2
```


#### List content of a user authenticated AWS bucket

```bash
# Create a free AWS account : https://console.aws.amazon.com/iam/home?#/security_credentials
aws configure --profile th1b4ud                                 # Add your AWS profile to AWS CLI
aws s3 --profile th1b4ud ls s3://authenticate-website.cloud     # List content of an AWS bucket with a profile
```

#### Download all the content of an AWS bucket

```
aws s3 sync s3://website.cloud/ . --no-sign-request --region us-west-2
```


#### Concept of Google Cloud bucket :

https://cloud.google.com/compute/docs/gcloud-compute/

https://cloud.google.com/sdk/docs/quickstart-linux

https://developers.google.com/identity/protocols/OAuth2ServiceAccount#creatingjwt


#### Learn more

If you want to learn more about AWS pentest, look at this website : http://flaws.cloud/



## Cryptography


#### Pigpen cipher

![](/img/neverlanctf/pigpen.jpg)

The Pigpen cipher is a simple substitution cipher based on a mnemonic geometric construction. 

You can encrypt/decrypt a message here : https://www.dcode.fr/chiffre-pig-pen-francs-macons

Writeup : https://github.com/str0nkus/NeverlanCTF-2019-Writeups/tree/master/Crypto/Oink_Oink


#### Babylonian alphabet

![](/img/neverlanctf/babylonian.png)

You can encode/decode a message here : https://www.dcode.fr/nombres-babyloniens

Writeup : https://github.com/str0nkus/NeverlanCTF-2019-Writeups/tree/master/Crypto/Super_Old_School


#### Substitution cipher

Substitution cipher is a method of encrypting by which units of plaintext are replaced with ciphertext, according to a fixed system.

Take a look to these tools :

- Usefull tool to test many encryption algorithms: https://cryptii.com/
- Usefull tool for substitution cipher : https://quipqiup.com/

Writeup : https://github.com/str0nkus/NeverlanCTF-2019-Writeups/tree/master/Crypto/Alphabet_Soup



## Bash

#### Bypass restricted bash

This type of exercise is quite common. You have to login but connection close after you type your creds.
For this trick I only add `exit` at the end of `/home/th1b4ud/.bashrc` file on `th1b4ud-vm`

```bash
[th1b4ud@th1b4ud-pc ~]$ ssh th1b4ud-vm
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

No, no, no ! Login is forbidden !

Connection to th1b4ud-vm closed.
```

So you can easily bypass with the `-t` option of ssh command line. 

```
-t      Force pseudo-terminal allocation.  This can be used to execute arbitrary screen-based programs on a remote machine, which can be very useful, e.g. when implementing menu services.
```

So we can execute command on the remote machine before the shell is loaded.

```
[th1b4ud@th1b4ud-pc ~]$ ssh th1b4ud-vm -t "/bin/sh"
$ id
uid=1000(th1b4ud) gid=1000(th1b4ud) groupes=1000(th1b4ud)
```

It's pretty cool. You can protect yourself about this bypass by adding `exit` at the start of your `.bashrc` file. But the best option is to deactivate the user in `/etc/ssh/sshd_config` like this : `DenyUsers <your_user>`



## Conclusion

So that's all for Neverlanctf 2019 ! My only regret is that I didn't solve the 4th binary. I think it's really simple but I'm very lame at reverse engineering. I'm waiting for writeup. It was a really nice ctf so see you next year :)

I hope you learned something from reading this article. Just copy/paste to your ctf cheatsheet, it's could be usefull :)

See you soon,

Th1b4ud