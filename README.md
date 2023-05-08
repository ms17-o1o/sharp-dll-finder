# sharp-dll-finder

## References:
[Hijack Libs](https://hijacklibs.net/)
[Hijack Libs Github Page](https://github.com/wietze/HijackLibs/wiki)

## Overview:
DLL hijacking is one of the offensive techniques that can be utilized to achieve persistence or possibly privilege escalation once initial access is
obtained. The aim of this project is to automate the process of searching for possible DLL hijacks opportunities on a Windows environment based
on a curated DLL list provided by [Hijack Libs](https://hijacklibs.net/?s=09).
## Types of DLL Hijacking Techniques:
**DLL Sideloading**. By copying (and optionally renaming) a vulnerable application to a user-writeable folder, alongside a malicious dll file,
arbitrary code can be executed through the legitimate application. See also MITRE ATT&CK® technique [T1574.002: Hijack Execution Flow:
DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/).
**DLL Environment Variable Hijacking**. By changing the environment variable (e.g. %SYSTEMROOT%) to an attacker-controlled directory, it is
possible to trick a vulnerable application into loading a malicious dll from the attacker-controlled location. See also MITRE ATT&CK®
technique [T1574: Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/).
**DLL Search Order Hijacking**. DLLs specified by an application without a path are searched for in fixed locations in a specific order. By putting
a malicious dll file in a location that is searched in before the actual DLL, the legitimate application will execute arbitrary code upon normal
execution.. See also MITRE ATT&CK® technique [T1574.001: Hijack Execution Flow: DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/).
Phantom DLL (Missing DLL) Hijacking. By copying a malicious missing dll file to a specific location, a vulnerable application will execute the
malicious DLL's code upon normal execution. See also MITRE ATT&CK® technique T1574.001: Hijack Execution Flow: DLL Search Order

## Hijacking.
### Curated List of DLL Hijacks:
The curated list of DLL by [Hijack Libs](https://hijacklibs.net/) is constantly being maintained and updated by public communities. The community project provides
defenders and red teamers valuable information to detect and create DLL Hijacking scenarios. The [github repo](https://github.com/wietze/HijackLibs/wiki) facilitates developers to contribute
and use the curated list via YAML.
### Automation in Detecting DLL Hijacking Candidates:
In a time-crunch situation like red teaming, it is often not practical to run through the entire list of DLL hijacking candidates on the website. A
helper file is created (using C#) to automatically enumerate possible DLL hijacking candidates based on the curated list provided by Hijack Libs.

![Screenshot1 of sharpdllfinder](https://github.com/ms17-o1o/sharp-dll-finder/raw/master/sharpdllfinderscreenshot1.png)
![Screenshot2 of sharpdllfinder](https://github.com/ms17-o1o/sharp-dll-finder/raw/master/sharpdllfinderscreenshot2.png)

## How to Use:
* Transfer the following files to a writable folder in victim windows machine (e.g. c:\users\public).
* sharp_dll_finder.exe - provided
* yml folder - provided (you can also download the latest from github repo).
* Run sharp_dll_finder.exe.
Follow the instructions on screen (make sure all directories entered to the program are writable by victim).
Extract the output file for reading.
Clean up.
