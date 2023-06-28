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

#include <sys/param.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/filio.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/selinfo.h>
#include <sys/signalfd.h>
#include <sys/signalvar.h>
#include <sys/stat.h>
#include <sys/sysproto.h>
#include <sys/uio.h>
#include <sys/user.h>

static MALLOC_DEFINE(M_SIGNALFD, "signalfd", "signalfd structures");

struct signalfd {
	sigset_t		sfd_mask;
	int			sfd_flags;
	struct mtx		sfd_lock;
	struct selinfo		sfd_sel;
	LIST_ENTRY(signalfd)	sfd_link;
};

void
signalfd_post(struct proc *p, int signo)
{
	struct signalfd *sfd;
	if (signo == SIGKILL || signo == SIGSTOP)
		return;
	LIST_FOREACH(sfd, &p->p_sfd, sfd_link) {
		mtx_lock(&sfd->sfd_lock);
		if (SIGISMEMBER(sfd->sfd_mask, signo))
			wakeup(&sfd->sfd_mask);
		mtx_unlock(&sfd->sfd_lock);
	}
}

static bool
signalfd_pending(struct proc *p, struct signalfd *sfd)
{
	int sig;
	SIG_FOREACH(sig, &p->p_siglist) {
		if (SIGISMEMBER(sfd->sfd_mask, sig))
			return (true);
	}
	return (false);
}

static void
sitossi(siginfo_t *si, struct signalfd_siginfo *ssi)
{
	_Static_assert(sizeof(*ssi) == 128, "signalfd_siginfo");
	ssi->ssi_signo =	si->si_signo;
	ssi->ssi_errno =	si->si_errno;
	ssi->ssi_code =		si->si_code;
	ssi->ssi_pid =		si->si_pid;
	ssi->ssi_uid =		si->si_uid;
	ssi->ssi_status =	si->si_status;
	ssi->ssi_addr =		(uint64_t)(uintptr_t)si->si_addr;
	ssi->ssi_int =		si->si_value.sival_int;
	ssi->ssi_ptr =		(uint64_t)(uintptr_t)si->si_value.sival_ptr;
	ssi->ssi_addr_lsb = 	ssi->ssi_addr & 0x1;

	/* Linux-specific fields. Extend later, if applicable. */
	ssi->ssi_fd =		-1;
	/* ssi->ssi_utime =	si-> */
	/* ssi->ssi_stime =	si-> */
	ssi->ssi_call_addr =	(uint64_t)(uintptr_t)NULL;
	/* ssi->ssi_arch =	si-> */

	/* Unioned fields. Only one at a time. */
	if (si->si_signo == SIGBUS) {
		ssi->ssi_trapno = si->si_trapno;
	} else if (si->si_code == SI_TIMER) {
		ssi->ssi_tid = si->si_timerid;
		ssi->ssi_overrun = si->si_overrun;
	} else if (si->si_code == SI_MESGQ) {
		ssi->ssi_fd = si->si_mqd;
	} else if (si->si_signo == SIGIO) {
		ssi->ssi_band = si->si_band;
	} else if (si->si_code == TRAP_CAP) {
		ssi->ssi_syscall = si->si_syscall;
	}
}

static int
signalfd_read(struct file *fp, struct uio *uio, struct ucred *active_cred,
    int flags, struct thread *td)
{
	struct signalfd *sfd = fp->f_data;
	struct signalfd_siginfo ssi;
	struct proc *p = td->td_proc;
	sigqueue_t *sq = &p->p_sigqueue;
	ksiginfo_t *ksi, *next;
	int error = 0;

	if (uio->uio_resid < sizeof(struct signalfd_siginfo))
		return (EINVAL);

retry:
	PROC_LOCK(p);
	mtx_lock(&sfd->sfd_lock);
	if (!signalfd_pending(p, sfd)) {
		if ((fp->f_flag & O_NONBLOCK) != 0) {
			error = EAGAIN;
			goto out;
		}
		PROC_UNLOCK(p);
		error = mtx_sleep(&sfd->sfd_mask, &sfd->sfd_lock,
		    PCATCH | PDROP, "sfdrd", 0);
		if (error != 0)
			return (error);
		goto retry;
	}

	TAILQ_FOREACH_SAFE(ksi, &sq->sq_list, ksi_link, next) {
		if (SIGISMEMBER(sfd->sfd_mask, ksi->ksi_signo)) {
			sitossi(&ksi->ksi_info, &ssi);
			error = uiomove_nofault(&ssi, sizeof(ssi), uio);
			if (error != 0)
				goto out;
			TAILQ_REMOVE(&sq->sq_list, ksi, ksi_link);
			ksi->ksi_sigq = NULL;
			if ((ksi->ksi_flags & KSI_EXT) == 0) {
				ksiginfo_free(ksi);
				--p->p_pendingcnt;
			}
		}
	}
	SIGSETNAND(sq->sq_kill, sfd->sfd_mask);
	SIGSETNAND(sq->sq_ptrace, sfd->sfd_mask);
	SIGSETNAND(sq->sq_signals, sfd->sfd_mask);

out:
	mtx_unlock(&sfd->sfd_lock);
	PROC_UNLOCK(p);
	return (error);
}

static int
signalfd_ioctl(struct file *fp, u_long cmd, void *data,
    struct ucred *active_cred, struct thread *td)
{
	switch (cmd) {
	case FIOASYNC:
		if (*(int *)data != 0)
			atomic_set_int(&fp->f_flag, O_ASYNC);
		else
			atomic_clear_int(&fp->f_flag, O_ASYNC);
		return (0);
	case FIONBIO:
		if (*(int *)data != 0)
			atomic_set_int(&fp->f_flag, O_NONBLOCK);
		else
			atomic_clear_int(&fp->f_flag, O_NONBLOCK);
		return (0);
	}
	return (ENOTTY);
}

static int
signalfd_poll(struct file *fp, int events, struct ucred *active_cred,
    struct thread *td)
{
	struct proc *p = td->td_proc;
	struct signalfd *sfd = fp->f_data;
	int revents = 0;

	PROC_LOCK(p);
	mtx_lock(&sfd->sfd_lock);
	if ((events & (POLLIN | POLLRDNORM)) != 0 &&
	    signalfd_pending(p, sfd))
		revents |= events & (POLLIN | POLLRDNORM);

	if (revents == 0)
		selrecord(td, &sfd->sfd_sel);
	mtx_unlock(&sfd->sfd_lock);
	PROC_UNLOCK(p);
	return (revents);
}

static void
filt_signalfddetach(struct knote *kn)
{
	struct signalfd *sfd = kn->kn_hook;

	mtx_lock(&sfd->sfd_lock);
	knlist_remove(&sfd->sfd_sel.si_note, kn, 1);
	mtx_unlock(&sfd->sfd_lock);
}

static int
filt_signalfdread(struct knote *kn, long hint)
{
	struct signalfd *sfd = kn->kn_hook;
	return (signalfd_pending(curthread->td_proc, sfd));
}

static struct filterops signalfd_rfiltops = {
	.f_isfd = 1,
	.f_detach = filt_signalfddetach,
	.f_event = filt_signalfdread,
};

static int
signalfd_kqfilter(struct file *fp, struct knote *kn)
{
	struct signalfd *sfd = fp->f_data;

	if (kn->kn_filter != EVFILT_READ)
		return (EINVAL);

	kn->kn_fop = &signalfd_rfiltops;
	kn->kn_hook = sfd;
	knlist_add(&sfd->sfd_sel.si_note, kn, 0);

	return (0);
}

static int
signalfd_stat(struct file *fp, struct stat *sb, struct ucred *active_cred)
{
	bzero(sb, sizeof(*sb));
	sb->st_nlink = fp->f_count - 1;
	sb->st_uid = fp->f_cred->cr_uid;
	sb->st_gid = fp->f_cred->cr_gid;
	sb->st_blksize = PAGE_SIZE;
	return (0);
}

static int
signalfd_close(struct file *fp, struct thread *td)
{
	struct proc *p = td->td_proc;
	struct signalfd *sfd = fp->f_data;

	PROC_LOCK(p);
	LIST_REMOVE(sfd, sfd_link);
	PROC_UNLOCK(p);
	seldrain(&sfd->sfd_sel);
	knlist_destroy(&sfd->sfd_sel.si_note);
	mtx_destroy(&sfd->sfd_lock);
	free(sfd, M_SIGNALFD);
	fp->f_ops = &badfileops;

	return (0);
}

static int
signalfd_fill_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp)
{

	struct signalfd *sfd = fp->f_data;

	kif->kf_type = KF_TYPE_SIGNALFD;
	mtx_lock(&sfd->sfd_lock);
	kif->kf_un.kf_signalfd.kf_signalfd_mask = (uintptr_t)&sfd->sfd_mask;
	kif->kf_un.kf_signalfd.kf_signalfd_flags = sfd->sfd_flags;
	kif->kf_un.kf_signalfd.kf_signalfd_addr = (uintptr_t)sfd;
	mtx_unlock(&sfd->sfd_lock);

	return (0);
}

static struct fileops signalfdops = {
	.fo_read = signalfd_read,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = signalfd_ioctl,
	.fo_poll = signalfd_poll,
	.fo_kqfilter = signalfd_kqfilter,
	.fo_stat = signalfd_stat,
	.fo_close = signalfd_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_fill_kinfo = signalfd_fill_kinfo,
	.fo_flags = DFLAG_PASSABLE,
};

int
kern_signalfd(struct thread *td, int fd, const sigset_t *mask, int flags)
{
	struct proc *p = td->td_proc;
	struct signalfd *sfd;
	struct file *fp;
	int error, fflags = 0;
	bool new = fd == -1 ? true : false;

	if ((flags & ~(SFD_NONBLOCK | SFD_CLOEXEC)) != 0)
		return (EINVAL);
	if ((flags & SFD_CLOEXEC) != 0)
		fflags |= O_CLOEXEC;

	if (new) {
		sfd = malloc(sizeof(*sfd), M_SIGNALFD, M_WAITOK | M_ZERO);
		if (sfd == NULL)
			return (ENOMEM);
		mtx_init(&sfd->sfd_lock, "signalfd", NULL, MTX_DEF);
		knlist_init_mtx(&sfd->sfd_sel.si_note, &sfd->sfd_lock);

		error = falloc(td, &fp, &fd, fflags);
		if (error != 0)
			return (error);
		fflags = FREAD;
		if ((flags & SFD_NONBLOCK) != 0)
			fflags |= O_NONBLOCK;
		finit(fp, fflags, DTYPE_SIGNALFD, sfd, &signalfdops);
	} else {
		error = fget(td, fd, &cap_write_rights, &fp);
		if (error != 0)
			return (error);
		sfd = fp->f_data;
		if (sfd == NULL || fp->f_type != DTYPE_SIGNALFD) {
			fdrop(fp, td);
			return (EINVAL);
		}
		mtx_lock(&sfd->sfd_lock);
		if ((flags & SFD_NONBLOCK) != 0)
			fp->f_flag |= O_NONBLOCK;
		else
			fp->f_flag &= ~O_NONBLOCK;
	}
	sfd->sfd_mask = *mask;
	SIG_CANTMASK(sfd->sfd_mask);
	sfd->sfd_flags = flags;
	if (new) {
		PROC_LOCK(p);
		LIST_INSERT_HEAD(&p->p_sfd, sfd, sfd_link);
		PROC_UNLOCK(p);
	} else {
		mtx_unlock(&sfd->sfd_lock);
	}

	fdrop(fp, td);
	td->td_retval[0] = fd;
	return (0);
}

int
sys_signalfd(struct thread *td, struct signalfd_args *uap)
{
	sigset_t mask;
	int error;

	error = copyin(uap->mask, &mask, sizeof(mask));
	if (error != 0)
		return (error);
	return (kern_signalfd(td, uap->fd, &mask, uap->flags));
}
