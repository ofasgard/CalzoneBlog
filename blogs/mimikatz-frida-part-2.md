---
title: Dumping Lsass with... Frida? (Part 2)
description: A blog about dynamic instrumentation of Lsass for fun and profit!
---

# Dumping Lsass with... Frida? (Part 2)

In the first chapter of this series, we stuck with Frida's core functionality - using its Interceptor module to hook and tamper with functions from *lsass.exe* and retrieve sensitive data passed to them. Our true goal, however, was to replicate the functionality of Mimikatz. To that end, let's have a look at how Mimikatz finds and decrypts credentials that have been cached in memory.

I found the following blogs very useful when I was trying to figure all this out:

- [XPN Infosec Blog - Exploring Mimikatz](https://blog.xpnsec.com/exploring-mimikatz-part-1/)
- [Uncovering Mimikatz ‘msv’ and collecting credentials through PyKD](https://www.matteomalvica.com/blog/2020/01/20/mimikatz-lsass-dump-windg-pykd/)

If you are interested in exploring this subject further or get stuck on your own implementations, I recommend checking them out. And of course, none of this would be possible without the incredible tool that is Mimikatz, and the reverse engineering and development that gentilkiwi continues to do on it.
