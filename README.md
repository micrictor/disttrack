Disttrak/Shamoon
====================

Reverse-engineered source code to the dropper for the Disttrak, AKA Shamoon, virus.

* Runs on 32 or 64-bit systems
* Attempts to spread to all connected Windows computers by trying to copy itself to every device on the same /24 network
* Time-delayed, with a built-in fallback date of 15 AUG 2012 @0808
* Three distinct components stored in the dropper as resources, disguised as PKI certificates
* Creates three executables for said compenents: trksrv.exe, netinit.exe, and one name randomly selected from a list
* Modifies the file created, accessed, and edited times for those executables to be the same as kernel32.dll to seem more legitimate