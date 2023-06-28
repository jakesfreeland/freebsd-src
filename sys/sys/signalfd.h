/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Jake Freeland <jfree@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SYS_SIGNALFD_H_
#define _SYS_SIGNALFD_H_

#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/proc.h>
#include <sys/selinfo.h>

/* Creation flags. */
#define SFD_NONBLOCK	O_NONBLOCK
#define SFD_CLOEXEC	O_CLOEXEC

/* Signal information returned by signalfd. */
struct signalfd_siginfo {
	uint32_t ssi_signo;
	int32_t  ssi_errno;
	int32_t  ssi_code;
	uint32_t ssi_pid;
	uint32_t ssi_uid;
	int32_t  ssi_fd;
	uint32_t ssi_tid;
	uint32_t ssi_band;
	uint32_t ssi_overrun;
	uint32_t ssi_trapno;
	int32_t  ssi_status;
	int32_t  ssi_int;
	uint64_t ssi_ptr;
	uint64_t ssi_utime;
	uint64_t ssi_stime;
	uint64_t ssi_addr;
	uint16_t ssi_addr_lsb;
	uint16_t __pad2;
	int32_t ssi_syscall;
	uint64_t ssi_call_addr;
	uint32_t ssi_arch;
	uint8_t __pad[28];
	/* sizeof(struct signalfd_siginfo) must be 128. */
};

#ifndef _KERNEL

__BEGIN_DECLS
int signalfd(int fd, const sigset_t *mask, int flags);
__END_DECLS

#else /* _KERNEL */

int kern_signalfd(struct thread *td, int fd, const sigset_t *mask, int flags);
void signalfd_post(struct proc *p, int signo);

#endif /* !_KERNEL */

#endif /* !_SYS_SIGNALFD_H_ */
