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

## Needles and Haystacks

Previously, we used Frida's Interceptor to attach to the *LsaApLogonUserEx2()* function and intercept credentials as they were passed to it. Having access to debugging functionality makes this an easy thing to do, but Mimikatz doesn't have that luxury. It needs to directly scan the memory allocated to the Lsass process, and somehow identify exactly where those credentials are stored. Only then can it actually begin parsing and decrypting those structures in memory.

We can look at the [Mimikatz source code](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa_utils.c) to figure out exactly how it accomplishes this. The answer is simpler than you may think - a hardcoded set of signatures is used to scan memory for the regions we're interested in. These signatures are obviously platform-dependent and are liable to change between different versions of Windows, so Mimikatz keeps several on them on-hand. Here is an example from the Mimikatz source:

```c
#elif defined(_M_X64)
BYTE PTRN_WIN5_LogonSessionList[]	= {0x4c, 0x8b, 0xdf, 0x49, 0xc1, 0xe3, 0x04, 0x48, 0x8b, 0xcb, 0x4c, 0x03, 0xd8};
BYTE PTRN_WN60_LogonSessionList[]	= {0x33, 0xff, 0x45, 0x85, 0xc0, 0x41, 0x89, 0x75, 0x00, 0x4c, 0x8b, 0xe3, 0x0f, 0x84};
BYTE PTRN_WN61_LogonSessionList[]	= {0x33, 0xf6, 0x45, 0x89, 0x2f, 0x4c, 0x8b, 0xf3, 0x85, 0xff, 0x0f, 0x84};
BYTE PTRN_WN63_LogonSessionList[]	= {0x8b, 0xde, 0x48, 0x8d, 0x0c, 0x5b, 0x48, 0xc1, 0xe1, 0x05, 0x48, 0x8d, 0x05};
BYTE PTRN_WN6x_LogonSessionList[]	= {0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74};
BYTE PTRN_WN1703_LogonSessionList[]	= {0x33, 0xff, 0x45, 0x89, 0x37, 0x48, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74};
BYTE PTRN_WN1803_LogonSessionList[] = {0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74};
BYTE PTRN_WN11_LogonSessionList[]	= {0x45, 0x89, 0x34, 0x24, 0x4c, 0x8b, 0xff, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74};
```

We can use these precompiled signatures in our own code, although we could also deduce them ourselves with a little reverse engineering and a debugger such as IDA or WinDBG. We'll cover exactly how these signatures were found in more detail later. For now, all we need is a way to scan memory for a specific sequence of bytes, which happily Frida provides for us:

```javascript
var lsasrv = Process.getModuleByName("lsasrv.dll")
var sequence = "33 ff 41 89 37 4c 8b f3 45 85 c9 74"; 

Memory.scan(lsasrv.base, lsasrv.size, sequence, {
	onMatch(signature, size) {
		console.log("Found a match at " + signature);
	}
});
```

With that, we have a way to scan the memory space of *lsasrv.dll* for those specific sequences. Mimikatz uses these signatures to deduce the address of specific global variables that contain sensitive data, and that's what we're going to need to do as well.

## Finding LogonSessionList

The first global variable we're interested in is *lsasrv!LogonSessionList*. As the name implies, this is a linked list where every element represents a single credential cached in memory. The way Mimikatz finds this variable is clever; it needs to find an instruction in *lsasrv.dll* which dereferences the address of the variable. This instruction will look something like this:

```asm
lea rcx, [rip + 0x118061] ; LogonSessionList
```

Note that the address itself is a %rip-relative offset (0x118061), which is determined at runtime. We're scanning memory at runtime, though, so as long as we can find the offset, we can perform some simple pointer arithmetic to find the actual address of the variable.
