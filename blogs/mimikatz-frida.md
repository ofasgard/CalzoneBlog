---
title: Dumping Lsass with... Frida?
description: todo
---

# Dumping Lsass with... Frida?

Recently I've been getting into [Frida](https://frida.re/), a great debugging and dynamic instrumentation tool with cross-platform support. Before I started getting into it, I'd only ever heard of it as a tool for reverse engineering black box mobile apps on iOS and Android. However, I think Frida has just as much potential as a rapid prototyping tool for reverse engineering and exploit development. Cross-platform support and a Javascript-based debugging language (I was skeptical at first too) means it's excellent for experimenting and tinkering with a process.

I've had advice in the past that writing your own Mimikatz implementation is one of the best ways to get familiar working with memory hacking in Windows. Writing something like this in Frida isn't something I've seen anyone else do, so I felt it would be a good challenge. An lsass dumper that requires you to run and connect to Frida server on the target probably wouldn't be your first choice on an engagement, but I hoped that the simplicity of Frida's debugging language would result in a kind of "pseudocode" dumper that could be trivially ported to other languages.

So, without further ado: let's talk about lsass!

## Step 1: Exploring Lsass

There are a wealth of tools, tutorials and guides out there that discuss both how mimikatz works and how to write your own tools to dump credentials from the process memory of lsass. I wanted to make a start completely blind, though, and see what I could discover with Frida alone.


<!--
Resources that helped me, which I should credit:

https://blog.xpnsec.com/exploring-mimikatz-part-1/
https://www.matteomalvica.com/blog/2020/01/20/mimikatz-lsass-dump-windg-pykd/
-->
