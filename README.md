# sau
Sshd AUdit - library to enhance sshd logging on RHEL9

Library to be loaded in sshd using LD_PRELOAD. Enhance logging capabilities og sshd.

* Logging of connect() done by tcp forwarding, use of Proxyjump or other
* Logging of execve() user, sid, ppid, args and sha256 hash of binary

Example:
```
Dec 30 21:45:49 rocky9-1 sau[2461]: [sau] execve() - USER=user UID=1000 SID=2237 PPID=2237 CMD=[ls --color=auto -al] FILE=[/usr/bin/ls] SHA256=[f6cf0eeebb08670be02f32c34076f0d49fc15c559a1f138241edf054c8e2a749]
Dec 30 21:45:59 rocky9-1 sau[2462]: [sau] execve() - USER=user UID=1000 SID=2237 PPID=2237 CMD=[nc 127.0.0.1 22] FILE=[/usr/bin/nc] SHA256=[59b59e934e7856e828994c92a3a9ebe08d5a269fc1b5d2b76066006fa10e7b87]
Dec 30 21:45:59 rocky9-1 sau[2462]: [sau] connect() - USER=user PID=2462 SID=2237 PPID=2237 to 127.0.0.1:22 (result=-1, errno=115)
```



