+++
categories = ["Articles", "Docker", "Misc"]
date = "2020-02-01"
title = "[MISC] Kali Linux in 3 seconds with Docker"
subtitle = "Because my time is too valuable !"
thumbnail = "/img/docker.png"
nopaging = "true"
+++


I'm sure you have already been in the same situation than me. You're working at a client's house for a penetration test, a tight time slot for your tests, no downtime. You arrive a little late in the morning (thanks to the strikes) and your virtual machine containing all your tools doesn't want to start (I knew I shouldn't have play with my bootloader yesterday night tss).

No choice, you have to reinstall this machine. And rapidly !

_... 30 minutes later ..._

**Ho God finished ! Why dit it takes so long to install a s\*\*\*y debian ??**

_... 5 minutes later ..._

**F\*\* why is it so long to boot ? And this dekstop pfff. Why there is no i3 default desktop ???**

```md
kali@tools:~$ cme
bash: cme: command not found
```

**FFF\*\*\* why CrackMapExec is not installed by default ??**

STOP ! If you've already been is this situation before, this article is for you ;)
Have you ever heard of Docker ? Yes I hope ! Docker provides applications through containerisation technology. It's a really mainstream and usefull technology.

I will not describe here how docker works, the docs is already very good : https://docs.docker.com/engine/docker-overview/

I think you've got it, we're going to use Docker for our offensive use. So I wrote a small Dockerfile and docker-compose file to build a light kali image with usefull tools. Project : https://github.com/thibaudrobin/docker-kali-light. Let's go into a little bit of detail.


## 1. Install docker

First you need to install Docker obviously. The documentation is really clear.

### For Linux

1. Follow the doc https://docs.docker.com/install/
2. Make docker work with your main user : https://docs.docker.com/install/linux/linux-postinstall/


### For Windows : 

1. Open the official documentation : https://docs.docker.com/docker-for-windows/install
2. Grab account credentials on BugMeNot : http://bugmenot.com/view/id.docker.com
3. Go to https://hub.docker.com/?overlay=onboarding to download Docker client.
4. Install Hyper-V : https://docs.microsoft.com/fr-fr/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v
    - Open a PowerShell console as an administrator.
    - Type command : `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All`

{{< warning "Warning, unfortunately it's not possible to have Hyper-V with VMware or Virtualbox :'(. You will have to choose one of three systems." >}}




## 2. Create a nice Dockerfile

Ok now that you have Docker, we can build our own Kali image. All the images are available online (https://www.kali.org/news/official-kali-linux-docker-images/) but none of them are really interresting. Below are all the tools I need : 

```md
aircrack-ng
crackmapexec
crunch
curl
dirb
dirbuster
dnsenum
dnsrecon
dnsutils
dos2unix
enum4linux
exploitdb
ftp
git
gobuster
hashcat
hping3
hydra
impacket-scripts
john
joomscan
masscan
metasploit-framework
mimikatz
nasm
ncat
netcat-traditional
nikto
nmap
patator
php
powersploit
proxychains
python-impacket
python-pip
python2
python3
recon-ng
responder
samba
samdump2
smbclient
smbmap
snmp
socat
sqlmap
sslscan
sslstrip
theharvester
vim
wafw00f
weevely
wfuzz
whois
wordlists
wpscan
```

If you check Kali metapackages (https://tools.kali.org/kali-metapackages), you will always see packages with too much tools or not enough. The kali-light metapackage is a real joke (there is 0 offensive tools wtf). Let's build a REAL `kali-light` image without burp, firefox and all other useless tools in docker.

`Dockerfile` file

```bash
# Dockerfile kali-light

# Official base image
FROM kalilinux/kali-rolling

# Apt
RUN apt -y update && apt -y upgrade && apt -y autoremove && apt clean

# Tools
RUN apt install aircrack-ng crackmapexec crunch curl dirb dirbuster dnsenum dnsrecon dnsutils dos2unix enum4linux exploitdb ftp git gobuster hashcat hping3 hydra impacket-scripts john joomscan masscan metasploit-framework mimikatz nasm ncat netcat-traditional nikto nmap patator php powersploit proxychains python-impacket python-pip python2 python3 recon-ng responder samba samdump2 smbclient smbmap snmp socat sqlmap sslscan sslstrip theharvester vim wafw00f weevely wfuzz whois wordlists wpscan -y --no-install-recommends

# Alias
RUN echo "alias l='ls -al'" >> /root/.bashrc
RUN echo "alias nse='ls /usr/share/nmap/scripts | grep '" >> /root/.bashrc
RUN echo "alias scan-range='nmap -T5 -n -sn'" >> /root/.bashrc
RUN echo "alias http-server='python3 -m http.server 8080'" >> /root/.bashrc
RUN echo "alias php-server='php -S 127.0.0.1:8080 -t .'" >> /root/.bashrc
RUN echo "alias ftp-server='python -m pyftpdlib -u \"admin\" -P \"S3cur3d_Ftp_3rv3r\" -p 2121'" >> /root/.bashrc

# Set working directory to /root
WORKDIR /root

# Open shell
CMD ["/bin/bash"]
```


## 3. Build your new image

You can now create the image with command : `docker build -t kali-light .`

```md
[th1b4ud@th1b4ud-pc ~]$ mkdir kali-light
[th1b4ud@th1b4ud-pc ~]$ cd kali-light/
[th1b4ud@th1b4ud-pc kali-light]$ docker build -t kali-light .
Sending build context to Docker daemon  3.072kB
Step 1/11 : FROM kalilinux/kali-rolling
 ---> b379e18689e6
Step 2/11 : RUN apt -y update && apt -y upgrade && apt -y autoremove && apt clean
 ---> Running in 0abf61ba9ad5

[...]

Need to get 611 MB of archives.

Step 11/11 : CMD ["/bin/bash"]
 ---> Running in 97bf4e6e2db5
Removing intermediate container 97bf4e6e2db5
 ---> e38e1334fdca
Successfully built e38e1334fdca
Successfully tagged kali-light:latest
```

As you can see, our new image has only 500MB of tools to download. It should download quickly. :D



## 4. Write Docker compose file

Now that we have built our new image, we can write a Docker compose file to facilitate container deployment. This will allow us to, for example, create a container with a directory shared with our host. In our case, we will share `/mnt/share-kali-light` from our host to `/share` directory in containers.

`docker-compose.yml` file

```bash
version: '3'

services:
  kali-light:
    image: "kali-light"
    volumes:
      - /mnt/share-kali-light:/share
```


## 5. Create containers

We can now deploy containers with the docker-compose command. First install it.

```md
[th1b4ud@th1b4ud-pc kali-light]$ pip install docker-compose --user
Collecting docker-compose
```

And always in working directory launch docker-compose.

```md
[th1b4ud@th1b4ud-pc kali-light]$ sudo mkdir /mnt/share-kali-light
[th1b4ud@th1b4ud-pc kali-light]$ docker-compose run kali-light
root@08cb02395204:~# l
total 16
drwx------ 1 root root 4096 Jan 26 04:20 .
drwxr-xr-x 1 root root 4096 Feb  8 15:09 ..
-rw-r--r-- 1 root root  844 Feb  8 01:36 .bashrc
-rw-r--r-- 1 root root  148 Jan 17 17:22 .profile
```

We can verify that we have our shared directory.

```md
[th1b4ud@th1b4ud-pc kali-light]$ echo "OK" > /mnt/share-kali-light/OK

root@08cb02395204:~# l /share/; cat /share/OK
total 12
drwxr-xr-x 2 1000 1000 4096 Feb  8 15:13 .
drwxr-xr-x 1 root root 4096 Feb  8 15:09 ..
-rw-r--r-- 1 1000 1000    3 Feb  8 15:12 OK
OK
```

Perfect !

By exiting the container with the command 'exit' we can see that it is still present. We can easily remove it with the `docker container rm <id>` command.

```md
[th1b4ud@th1b4ud-pc kali-light]$ docker ps -a
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS                     PORTS               NAMES
08cb02395204        kali-light          "/bin/bash"         4 minutes ago       Exited (0) 4 seconds ago                       kali-light_kali-light_run_9e9e44eb9410

[th1b4ud@th1b4ud-pc kali-light]$ docker container rm 08
08

[th1b4ud@th1b4ud-pc kali-light]$ docker ps -a
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
```

We can also launch container from others directory.

```md
[th1b4ud@th1b4ud-pc ~]$ docker-compose -f /home/th1b4ud/kali-light/docker-compose.yml run kali-light
root@07a9e76dfb70:~# 
```

## 6. Create some alias

Usefull alias for your .bashrc. Don't forget to change the location of the project !

```bash
echo "alias kali='docker-compose -f $HOME/kali-light/docker-compose.yml run kali-light'" >> .bashrc && source .bashrc
```

All the files used are available on my github : https://github.com/thibaudrobin/docker-kali-light

That's all ! Enjoy :)

Th1b4ud