---
title: Dumping Lsass with... Frida?
---

# Dumping Lsass with... Frida?

Recently I've been getting into [Frida](https://frida.re/), a great debugging and dynamic instrumentation tool with cross-platform support. Before I looked into it, I'd only ever heard of Frida as a tool for hacking mobile apps - I'd never considered it for anything else. However, I think Frida has just as much potential as a rapid prototyping tool for reverse engineering and exploit development. It's agile, portable and fast, which makes it an excellent choice for experimenting and tinkering with a process.

I've had advice in the past that writing your own Mimikatz implementation is one of the best ways to get familiar working with memory hacking in Windows. Writing something like this in Frida isn't something I've seen anyone else do, so I felt it would be a good challenge. How can you use Frida to dump Lsass?

A credential dumper that requires you to execute and connect to a Frida server on the target probably wouldn't be your first choice on an engagement, but I hoped that the simplicity of Frida's debugging language would result in a kind of "intermediary" tool that could be trivially ported to other languages. So without further ado, let's break Lsass!

## Step 1: Exploring Lsass

You can find a wealth of tools and tutorials out there which discuss how mimikatz works and how to dump credentials from the process memory of Lsass. I wanted to make a start completely blind, though, and see what I could discover with Frida alone.


<!--
Resources that helped me, which I should credit:

https://blog.xpnsec.com/exploring-mimikatz-part-1/
https://www.matteomalvica.com/blog/2020/01/20/mimikatz-lsass-dump-windg-pykd/
-->
