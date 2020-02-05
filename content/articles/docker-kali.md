+++
categories = ["Articles", "Docker", "Misc"]
date = "2020-02-01"
title = "[MISC] Kali Linux in 3 seconds with Docker"
subtitle = "Because my time is too valuable !"
thumbnail = "/img/docker.png"
nopaging = "true"
draft = "false"
+++


I'm sure you have already been in the same situation than me. You're working at a client's house for a penetration test, a tight time slot for your tests, no downtime. You arrive a little late in the morning (thanks to the strikes) and your virtual machine containing all your tools doesn't want to start (I knew I shouldn't have to play with my bootloader yesterday night tss).

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

I think you've got it, we're going to use Docker for our offensive use.



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




## 2. Pull Kali Linux image

Ok now that you have Docker, you can pull an image of Kali Linux. All the images are available online : https://www.kali.org/news/official-kali-linux-docker-images/


```md
[th1b4ud@th1b4ud-pc ~]$ docker pull kalilinux/kali-rolling

Using default tag: latest
latest: Pulling from kalilinux/kali-rolling
4336943deccf: Pull complete 
Digest: sha256:7579af6e4be669ecd3c338c2de3c77e1f8dc0caa49bdce5a017bc0a1dcd7458e
Status: Downloaded newer image for kalilinux/kali-rolling:latest
```


## 3. Create a new container

You can create a Docker container from the kali image with the following command :

```md
[th1b4ud@th1b4ud-pc ~]$ docker run -it --name kali-light kalilinux/kali-rolling /bin/bash

root@fff3eb4d0e85:/#
```

The command created a container called `kali-light`.
Next inside the container you can install all your tools. Basic kali image only came with kali repository.

Classic update and upgrade 

```md
root@fff3eb4d0e85:/# apt update && apt dist-upgrade
```

And install some basic tools : https://www.kali.org/news/kali-linux-metapackages/

```md
root@fff3eb4d0e85:/# apt install kali-linux-top10
```

{{< protips "If you don't want to waste your time in installation you can pull unofficial Kali image with already all the tools installed (ex : linuxkonsult/kali-metasploit). More info with the command : docker search kali" >}}


## 4. Save your image

Now that you've customized your kali container, you should save it as a new image.
In your container just type `exit` to exit from your container. It will just stop it.

To see all of your containers :

```md
[th1b4ud@th1b4ud-pc ~]$ docker ps -a
6b1bebcd51f1        c41558768dba        "/bin/bash"         7 minutes ago        Exited (0) About a minute ago                         kali-light
```

All your work are on this container.

First argument is your container name and the second your new image name. Syntax : `docker commit <container> <image>`

```md
[th1b4ud@th1b4ud-pc ~]$ docker commit kali-light kali-light

sha256:c136e2f817a595078bdd8b304d2f97237582c330f6e08808a33a4a93b988c251
```

You can check if your image is correctly saved

```md
[th1b4ud@th1b4ud-pc ~]$ docker image ls

REPOSITORY               TAG                 IMAGE ID            CREATED             SIZE
kali-light               latest              c136e2f817a5        16 seconds ago      1.2GB
kalilinux/kali-rolling   latest              653a51597fe9        19 hours ago        113MB
```

Done ! Now if you destroy your fresh container, you can easily create an other one from your customized image.


## 5. Create some alias

Your old container is not deleted but just stopped. So you don't need to recreate a new one each time. Just callit with the command :

Start it :
`docker start kali-light`

And access to it :
`docker exec -it kali-light /bin/bash`

And create an alias in your .bashrc :

`echo "alias kali='docker start kali-light > /dev/null && docker exec -it kali-light /bin/bash'" >> .bashrc && source .bashrc`

That's all ! If you want to share your own pimped kali image don't forget to commit your container before ;)
