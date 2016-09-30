# Irsssi seccomp plugin

This plugin aims at adding a bit of security to Irssi thanks to
[seccomp](https://en.wikipedia.org/wiki/Seccomp). Syscalls that aren't vital to
Irssi (`execve` for instance) aren't allowed. If a forbidden syscall happen, the
Irssi process is immediately killed without executing it.

Unfortunately, seccomp alone isn't bulletproof since an attacker can still
access to the filesystem. Running Irssi inside a chroot is recommended.

[namnamc](https://github.com/namnamc) already wrote a
[pull request](https://github.com/irssi/irssi/pull/342/files) to add seccomp
support to Irssi, but it has never been merged.


## Requirements

Header files:

    $ sudo apt install irssi-dev


## Build

    $ make

A complete build of Irssi isn't required since `module_register()` is resolved
by `dlsym()`.


## Cross compilation (arm)

`glib-2.0` headers must copied in `arm/` folder.

    $ sudo apt install gcc-arm-linux-gnueabihf
    $ ARM=1 make


## Irssi configuration

## Manual load

    /load /home/user/.irssi/modules/seccomp.so



## Automatic load

To ensure that the plugin is loaded when Irssi starts, add the following line to
`~/.irssi/config`:

	/load /home/user/.irssi/modules/seccomp.so



## How to verify that Irssi is effectively seccomped?

Since the `execve` syscall is forbidden by seccomp, the `/exec` command can be
used to trigger a warning (Irssi isn't killed because it forks beforce executing
the specified command in the background, and the `clone` syscall is allowed):

    /exec uname
    13:36 -!- Irssi: process 0 (uname) terminated with signal 31 (Bad system call)

The `/proc` filesystem gives some
[informations](http://man7.org/linux/man-pages/man5/proc.5.html) (`0` means
`SECCOMP_MODE_DISABLED`; `1` means `SECCOMP_MODE_STRICT`; `2` means
`SECCOMP_MODE_FILTER`):

    $ grep Seccomp /proc/$(pidof irssi)/status
	Seccomp:	2


## How to add a new syscall?

If Irssi is killed and your shell displays `Bad system call`, you may try to
append the culprit syscall to the allowed list in `seccomp.c`. Use `dmesg` to
get the syscall number:

    $ dmesg | tail -1
    [21102.750355] audit: type=1326 audit(1475161330.424:30): auid=4294967295 uid=1000 gid=1000 ses=4294967295 pid=19717 comm="irssi" exe="/usr/bin/irssi" sig=31 arch=c000003e syscall=112 compat=0 ip=0x7fee729a9a67 code=0x0

Find the corresponding syscall:

    $ grep -r 112 /usr/include/ | grep __NR
    /usr/include/x86_64-linux-gnu/asm/unistd_64.h:#define __NR_setsid 112

And add it to `seccomp.c`:

    ALLOW_SYSCALL(setsid),
