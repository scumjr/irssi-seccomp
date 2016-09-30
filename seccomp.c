#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

#include "seccomp-bpf.h"

#define IRSSI_ABI_VERSION	2

static int load_seccomp(void)
{
	struct sock_filter filter[] = {
		/* Validate architecture. */
		VALIDATE_ARCHITECTURE,
		/* Grab the system call number. */
		EXAMINE_SYSCALL,
		/* List allowed syscalls. */
		ALLOW_SYSCALL(access),
		ALLOW_SYSCALL(bind),
		ALLOW_SYSCALL(brk),
		ALLOW_SYSCALL(clone),
		ALLOW_SYSCALL(close),
		ALLOW_SYSCALL(connect),
		ALLOW_SYSCALL(eventfd2),
		ALLOW_SYSCALL(exit),
		ALLOW_SYSCALL(exit_group),
		ALLOW_SYSCALL(fcntl),
		ALLOW_SYSCALL(fstat),
		ALLOW_SYSCALL(futex),
		ALLOW_SYSCALL(getdents),
		ALLOW_SYSCALL(getdents64),
		ALLOW_SYSCALL(getegid),
		ALLOW_SYSCALL(geteuid),
		ALLOW_SYSCALL(getgid),
		ALLOW_SYSCALL(getsockname),
		ALLOW_SYSCALL(getsockopt),
		ALLOW_SYSCALL(getuid),
		ALLOW_SYSCALL(ioctl),
		ALLOW_SYSCALL(kill),
		ALLOW_SYSCALL(lseek),
		ALLOW_SYSCALL(mkdir),
		ALLOW_SYSCALL(mprotect),
		ALLOW_SYSCALL(munmap),
		ALLOW_SYSCALL(open),
		ALLOW_SYSCALL(pipe),
		ALLOW_SYSCALL(poll),
		ALLOW_SYSCALL(prctl),
		ALLOW_SYSCALL(read),
		ALLOW_SYSCALL(readlink),
		ALLOW_SYSCALL(recvfrom),
		ALLOW_SYSCALL(recvmsg),
		ALLOW_SYSCALL(restart_syscall),
		ALLOW_SYSCALL(rt_sigaction),
		ALLOW_SYSCALL(rt_sigprocmask),
		ALLOW_SYSCALL(rt_sigreturn),
		ALLOW_SYSCALL(sendmmsg),
		ALLOW_SYSCALL(sendto),
		ALLOW_SYSCALL(setrlimit),
		ALLOW_SYSCALL(set_robust_list),
		ALLOW_SYSCALL(setsockopt),
		ALLOW_SYSCALL(set_tid_address),
		ALLOW_SYSCALL(socket),
		ALLOW_SYSCALL(stat),
		ALLOW_SYSCALL(uname),
		ALLOW_SYSCALL(wait4),
		ALLOW_SYSCALL(write),
#if defined(__arm__)
		ALLOW_SYSCALL(fcntl64),
		ALLOW_SYSCALL(fstat64),
		ALLOW_SYSCALL(getegid32),
		ALLOW_SYSCALL(geteuid32),
		ALLOW_SYSCALL(getgid32),
		ALLOW_SYSCALL(getuid32),
		ALLOW_SYSCALL(_llseek),
		ALLOW_SYSCALL(mmap2),
		ALLOW_SYSCALL(_newselect),
		ALLOW_SYSCALL(send),
		ALLOW_SYSCALL(sigreturn),
		ALLOW_SYSCALL(stat64),
		ALLOW_SYSCALL(ugetrlimit),
#else
		ALLOW_SYSCALL(arch_prctl),
		ALLOW_SYSCALL(getrlimit),
		ALLOW_SYSCALL(mmap),
		ALLOW_SYSCALL(select),
#endif
		KILL_PROCESS,
	};

	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		fprintf(stderr, "prctl(NO_NEW_PRIVS)\n");
		return -1;
	}

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		fprintf(stderr, "prctl(SECCOMP)");
		return -1;
	}

	return 0;
}

void seccomp_init(void)
{
	void (*module_register_full)(const char *, const char *, const char *);

	/* this is dirty but easier than having to compile irssi... */
	dlerror();
	module_register_full = dlsym(RTLD_DEFAULT, "module_register_full");
	if (dlerror() != NULL) {
		fprintf(stderr, "failed to resolve module_register_full\n");
		exit(1);
	}

	if (load_seccomp() != 0)
		exit(1);

	module_register_full("seccomp", "core", "seccomp");
}

void seccomp_deinit(void)
{
}

#ifdef IRSSI_ABI_VERSION
void seccomp_abicheck(int *version)
{
	*version = IRSSI_ABI_VERSION;
}
#endif
