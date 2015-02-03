/* Target-dependent code for GNU/Linux AArch64.

   Copyright (C) 2009-2015 Free Software Foundation, Inc.
   Contributed by ARM Ltd.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"

#include "gdbarch.h"
#include "glibc-tdep.h"
#include "linux-tdep.h"
#include "aarch64-tdep.h"
#include "aarch64-linux-tdep.h"
#include "osabi.h"
#include "solib-svr4.h"
#include "symtab.h"
#include "tramp-frame.h"
#include "trad-frame.h"

#include "inferior.h"
#include "regcache.h"
#include "regset.h"

#include "cli/cli-utils.h"
#include "stap-probe.h"
#include "parser-defs.h"
#include "user-regs.h"
#include <ctype.h>

#include "record-full.h"
#include "linux-record.h"

/* Signal frame handling.

      +------------+  ^
      | saved lr   |  |
   +->| saved fp   |--+
   |  |            |
   |  |            |
   |  +------------+
   |  | saved lr   |
   +--| saved fp   |
   ^  |            |
   |  |            |
   |  +------------+
   ^  |            |
   |  | signal     |
   |  |            |        SIGTRAMP_FRAME (struct rt_sigframe)
   |  | saved regs |
   +--| saved sp   |--> interrupted_sp
   |  | saved pc   |--> interrupted_pc
   |  |            |
   |  +------------+
   |  | saved lr   |--> default_restorer (movz x8, NR_sys_rt_sigreturn; svc 0)
   +--| saved fp   |<- FP
      |            |         NORMAL_FRAME
      |            |<- SP
      +------------+

  On signal delivery, the kernel will create a signal handler stack
  frame and setup the return address in LR to point at restorer stub.
  The signal stack frame is defined by:

  struct rt_sigframe
  {
    siginfo_t info;
    struct ucontext uc;
  };

  typedef struct
  {
    ...                                    128 bytes
  } siginfo_t;

  The ucontext has the following form:
  struct ucontext
  {
    unsigned long uc_flags;
    struct ucontext *uc_link;
    stack_t uc_stack;
    sigset_t uc_sigmask;
    struct sigcontext uc_mcontext;
  };

  typedef struct sigaltstack
  {
    void *ss_sp;
    int ss_flags;
    size_t ss_size;
  } stack_t;

  struct sigcontext
  {
    unsigned long fault_address;
    unsigned long regs[31];
    unsigned long sp;		/ * 31 * /
    unsigned long pc;		/ * 32 * /
    unsigned long pstate;	/ * 33 * /
    __u8 __reserved[4096]
  };

  The restorer stub will always have the form:

  d28015a8        movz    x8, #0xad
  d4000001        svc     #0x0

  This is a system call sys_rt_sigreturn.

  We detect signal frames by snooping the return code for the restorer
  instruction sequence.

  The handler then needs to recover the saved register set from
  ucontext.uc_mcontext.  */

/* These magic numbers need to reflect the layout of the kernel
   defined struct rt_sigframe and ucontext.  */
#define AARCH64_SIGCONTEXT_REG_SIZE             8
#define AARCH64_RT_SIGFRAME_UCONTEXT_OFFSET     128
#define AARCH64_UCONTEXT_SIGCONTEXT_OFFSET      176
#define AARCH64_SIGCONTEXT_XO_OFFSET            8

/* Implement the "init" method of struct tramp_frame.  */

static void
aarch64_linux_sigframe_init (const struct tramp_frame *self,
			     struct frame_info *this_frame,
			     struct trad_frame_cache *this_cache,
			     CORE_ADDR func)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  CORE_ADDR sp = get_frame_register_unsigned (this_frame, AARCH64_SP_REGNUM);
  CORE_ADDR sigcontext_addr =
    sp
    + AARCH64_RT_SIGFRAME_UCONTEXT_OFFSET
    + AARCH64_UCONTEXT_SIGCONTEXT_OFFSET;
  int i;

  for (i = 0; i < 31; i++)
    {
      trad_frame_set_reg_addr (this_cache,
			       AARCH64_X0_REGNUM + i,
			       sigcontext_addr + AARCH64_SIGCONTEXT_XO_OFFSET
			       + i * AARCH64_SIGCONTEXT_REG_SIZE);
    }
  trad_frame_set_reg_addr (this_cache, AARCH64_SP_REGNUM,
			   sigcontext_addr + AARCH64_SIGCONTEXT_XO_OFFSET
			     + 31 * AARCH64_SIGCONTEXT_REG_SIZE);
  trad_frame_set_reg_addr (this_cache, AARCH64_PC_REGNUM,
			   sigcontext_addr + AARCH64_SIGCONTEXT_XO_OFFSET
			     + 32 * AARCH64_SIGCONTEXT_REG_SIZE);

  trad_frame_set_id (this_cache, frame_id_build (sp, func));
}

static const struct tramp_frame aarch64_linux_rt_sigframe =
{
  SIGTRAMP_FRAME,
  4,
  {
    /* movz x8, 0x8b (S=1,o=10,h=0,i=0x8b,r=8)
       Soo1 0010 1hhi iiii iiii iiii iiir rrrr  */
    {0xd2801168, -1},

    /* svc  0x0      (o=0, l=1)
       1101 0100 oooi iiii iiii iiii iii0 00ll  */
    {0xd4000001, -1},
    {TRAMP_SENTINEL_INSN, -1}
  },
  aarch64_linux_sigframe_init
};

/* Register maps.  */

static const struct regcache_map_entry aarch64_linux_gregmap[] =
  {
    { 31, AARCH64_X0_REGNUM, 8 }, /* x0 ... x30 */
    { 1, AARCH64_SP_REGNUM, 8 },
    { 1, AARCH64_PC_REGNUM, 8 },
    { 1, AARCH64_CPSR_REGNUM, 8 },
    { 0 }
  };

static const struct regcache_map_entry aarch64_linux_fpregmap[] =
  {
    { 32, AARCH64_V0_REGNUM, 16 }, /* v0 ... v31 */
    { 1, AARCH64_FPSR_REGNUM, 4 },
    { 1, AARCH64_FPCR_REGNUM, 4 },
    { 0 }
  };

/* Register set definitions.  */

const struct regset aarch64_linux_gregset =
  {
    aarch64_linux_gregmap,
    regcache_supply_regset, regcache_collect_regset
  };

const struct regset aarch64_linux_fpregset =
  {
    aarch64_linux_fpregmap,
    regcache_supply_regset, regcache_collect_regset
  };

/* Implement the "regset_from_core_section" gdbarch method.  */

static void
aarch64_linux_iterate_over_regset_sections (struct gdbarch *gdbarch,
					    iterate_over_regset_sections_cb *cb,
					    void *cb_data,
					    const struct regcache *regcache)
{
  cb (".reg", AARCH64_LINUX_SIZEOF_GREGSET, &aarch64_linux_gregset,
      NULL, cb_data);
  cb (".reg2", AARCH64_LINUX_SIZEOF_FPREGSET, &aarch64_linux_fpregset,
      NULL, cb_data);
}

/* Implementation of `gdbarch_stap_is_single_operand', as defined in
   gdbarch.h.  */

static int
aarch64_stap_is_single_operand (struct gdbarch *gdbarch, const char *s)
{
  return (*s == '#' || isdigit (*s) /* Literal number.  */
	  || *s == '[' /* Register indirection.  */
	  || isalpha (*s)); /* Register value.  */
}

/* This routine is used to parse a special token in AArch64's assembly.

   The special tokens parsed by it are:

      - Register displacement (e.g, [fp, #-8])

   It returns one if the special token has been parsed successfully,
   or zero if the current token is not considered special.  */

static int
aarch64_stap_parse_special_token (struct gdbarch *gdbarch,
				  struct stap_parse_info *p)
{
  if (*p->arg == '[')
    {
      /* Temporary holder for lookahead.  */
      const char *tmp = p->arg;
      char *endp;
      /* Used to save the register name.  */
      const char *start;
      char *regname;
      int len;
      int got_minus = 0;
      long displacement;
      struct stoken str;

      ++tmp;
      start = tmp;

      /* Register name.  */
      while (isalnum (*tmp))
	++tmp;

      if (*tmp != ',')
	return 0;

      len = tmp - start;
      regname = alloca (len + 2);

      strncpy (regname, start, len);
      regname[len] = '\0';

      if (user_reg_map_name_to_regnum (gdbarch, regname, len) == -1)
	error (_("Invalid register name `%s' on expression `%s'."),
	       regname, p->saved_arg);

      ++tmp;
      tmp = skip_spaces_const (tmp);
      /* Now we expect a number.  It can begin with '#' or simply
	 a digit.  */
      if (*tmp == '#')
	++tmp;

      if (*tmp == '-')
	{
	  ++tmp;
	  got_minus = 1;
	}
      else if (*tmp == '+')
	++tmp;

      if (!isdigit (*tmp))
	return 0;

      displacement = strtol (tmp, &endp, 10);
      tmp = endp;

      /* Skipping last `]'.  */
      if (*tmp++ != ']')
	return 0;

      /* The displacement.  */
      write_exp_elt_opcode (&p->pstate, OP_LONG);
      write_exp_elt_type (&p->pstate, builtin_type (gdbarch)->builtin_long);
      write_exp_elt_longcst (&p->pstate, displacement);
      write_exp_elt_opcode (&p->pstate, OP_LONG);
      if (got_minus)
	write_exp_elt_opcode (&p->pstate, UNOP_NEG);

      /* The register name.  */
      write_exp_elt_opcode (&p->pstate, OP_REGISTER);
      str.ptr = regname;
      str.length = len;
      write_exp_string (&p->pstate, str);
      write_exp_elt_opcode (&p->pstate, OP_REGISTER);

      write_exp_elt_opcode (&p->pstate, BINOP_ADD);

      /* Casting to the expected type.  */
      write_exp_elt_opcode (&p->pstate, UNOP_CAST);
      write_exp_elt_type (&p->pstate, lookup_pointer_type (p->arg_type));
      write_exp_elt_opcode (&p->pstate, UNOP_CAST);

      write_exp_elt_opcode (&p->pstate, UNOP_IND);

      p->arg = tmp;
    }
  else
    return 0;

  return 1;
}

/* AArch64 process record-replay constructs: syscall, signal etc.  */

struct linux_record_tdep aarch64_linux_record_tdep;

/* aarch64_canonicalize_syscall maps syscall ids from the native AArch64
   linux set of syscall ids into a canonical set of syscall ids used by
   process record.  */

static enum gdb_syscall
aarch64_canonicalize_syscall (enum aarch64_syscall syscall_number)
{
  switch (syscall_number) {
  case aarch64_sys_read:
    return gdb_sys_read;

  case aarch64_sys_write:
    return gdb_sys_write;

  case aarch64_sys_open:
    return gdb_sys_open;

  case aarch64_sys_close:
    return gdb_sys_close;

  case aarch64_sys_lseek:
    return gdb_sys_lseek;

  case aarch64_sys_mprotect:
    return gdb_sys_mprotect;

  case aarch64_sys_munmap:
    return gdb_sys_munmap;

  case aarch64_sys_brk:
    return gdb_sys_brk;

  case aarch64_sys_rt_sigaction:
    return gdb_sys_rt_sigaction;

  case aarch64_sys_rt_sigprocmask:
    return gdb_sys_rt_sigprocmask;

  case aarch64_sys_rt_sigreturn:
    return gdb_sys_rt_sigreturn;

  case aarch64_sys_ioctl:
    return gdb_sys_ioctl;

  case aarch64_sys_pread64:
    return gdb_sys_pread64;

  case aarch64_sys_pwrite64:
    return gdb_sys_pwrite64;

  case aarch64_sys_readv:
    return gdb_sys_readv;

  case aarch64_sys_writev:
    return gdb_sys_writev;

  case aarch64_sys_sched_yield:
    return gdb_sys_sched_yield;

  case aarch64_sys_mremap:
    return gdb_sys_mremap;

  case aarch64_sys_msync:
    return gdb_sys_msync;

  case aarch64_sys_mincore:
    return gdb_sys_mincore;

  case aarch64_sys_madvise:
    return gdb_sys_madvise;

  case aarch64_sys_shmget:
    return gdb_sys_shmget;

  case aarch64_sys_shmat:
    return gdb_sys_shmat;

  case aarch64_sys_shmctl:
    return gdb_sys_shmctl;

  case aarch64_sys_dup:
    return gdb_sys_dup;

  case aarch64_sys_nanosleep:
    return gdb_sys_nanosleep;

  case aarch64_sys_getitimer:
    return gdb_sys_getitimer;

  case aarch64_sys_setitimer:
    return gdb_sys_setitimer;

  case aarch64_sys_getpid:
    return gdb_sys_getpid;

  case aarch64_sys_sendfile:
    return gdb_sys_sendfile;

  case aarch64_sys_socket:
    return gdb_sys_socket;

  case aarch64_sys_connect:
    return gdb_sys_connect;

  case aarch64_sys_accept:
    return gdb_sys_accept;

  case aarch64_sys_sendto:
    return gdb_sys_sendto;

  case aarch64_sys_recvfrom:
    return gdb_sys_recvfrom;

  case aarch64_sys_sendmsg:
    return gdb_sys_sendmsg;

  case aarch64_sys_recvmsg:
    return gdb_sys_recvmsg;

  case aarch64_sys_shutdown:
    return gdb_sys_shutdown;

  case aarch64_sys_bind:
    return gdb_sys_bind;

  case aarch64_sys_listen:
    return gdb_sys_listen;

  case aarch64_sys_getsockname:
    return gdb_sys_getsockname;

  case aarch64_sys_getpeername:
    return gdb_sys_getpeername;

  case aarch64_sys_socketpair:
    return gdb_sys_socketpair;

  case aarch64_sys_setsockopt:
    return gdb_sys_setsockopt;

  case aarch64_sys_getsockopt:
    return gdb_sys_getsockopt;

  case aarch64_sys_clone:
    return gdb_sys_clone;

  case aarch64_sys_execve:
    return gdb_sys_execve;

  case aarch64_sys_exit:
    return gdb_sys_exit;

  case aarch64_sys_wait4:
    return gdb_sys_wait4;

  case aarch64_sys_kill:
    return gdb_sys_kill;

  case aarch64_sys_uname:
    return gdb_sys_uname;

  case aarch64_sys_semget:
    return gdb_sys_semget;

  case aarch64_sys_semop:
    return gdb_sys_semop;

  case aarch64_sys_semctl:
    return gdb_sys_semctl;

  case aarch64_sys_shmdt:
    return gdb_sys_shmdt;

  case aarch64_sys_msgget:
    return gdb_sys_msgget;

  case aarch64_sys_msgsnd:
    return gdb_sys_msgsnd;

  case aarch64_sys_msgrcv:
    return gdb_sys_msgrcv;

  case aarch64_sys_msgctl:
    return gdb_sys_msgctl;

  case aarch64_sys_fcntl:
    return gdb_sys_fcntl;

  case aarch64_sys_flock:
    return gdb_sys_flock;

  case aarch64_sys_fsync:
    return gdb_sys_fsync;

  case aarch64_sys_fdatasync:
    return gdb_sys_fdatasync;

  case aarch64_sys_truncate:
    return gdb_sys_truncate;

  case aarch64_sys_ftruncate:
    return gdb_sys_ftruncate;

  case aarch64_sys_getcwd:
    return gdb_sys_getcwd;

  case aarch64_sys_chdir:
    return gdb_sys_chdir;

  case aarch64_sys_fchdir:
    return gdb_sys_fchdir;

  case aarch64_sys_rename:
    return gdb_sys_rename;

  case aarch64_sys_mkdir:
    return gdb_sys_mkdir;

  case aarch64_sys_link:
    return gdb_sys_link;

  case aarch64_sys_unlink:
    return gdb_sys_unlink;

  case aarch64_sys_symlink:
    return gdb_sys_symlink;

  case aarch64_sys_readlink:
    return gdb_sys_readlink;

  case aarch64_sys_fchmodat:
    return gdb_sys_fchmodat;

  case aarch64_sys_fchmod:
    return gdb_sys_fchmod;

  case aarch64_sys_fchownat:
    return gdb_sys_fchownat;

  case aarch64_sys_fchown:
    return gdb_sys_fchown;

  case aarch64_sys_umask:
    return gdb_sys_umask;

  case aarch64_sys_gettimeofday:
    return gdb_sys_gettimeofday;

  case aarch64_sys_getrlimit:
    return gdb_sys_getrlimit;

  case aarch64_sys_getrusage:
    return gdb_sys_getrusage;

  case aarch64_sys_sysinfo:
    return gdb_sys_sysinfo;

  case aarch64_sys_ptrace:
    return gdb_sys_ptrace;

  case aarch64_sys_getuid:
    return gdb_sys_getuid;

  case aarch64_sys_syslog:
    return gdb_sys_syslog;

  case aarch64_sys_getgid:
    return gdb_sys_getgid;

  case aarch64_sys_setuid:
    return gdb_sys_setuid;

  case aarch64_sys_setgid:
    return gdb_sys_setgid;

  case aarch64_sys_geteuid:
    return gdb_sys_geteuid;

  case aarch64_sys_getegid:
    return gdb_sys_getegid;

  case aarch64_sys_setpgid:
    return gdb_sys_setpgid;

  case aarch64_sys_getppid:
    return gdb_sys_getppid;

  case aarch64_sys_setsid:
    return gdb_sys_setsid;

  case aarch64_sys_setreuid:
    return gdb_sys_setreuid;

  case aarch64_sys_setregid:
    return gdb_sys_setregid;

  case aarch64_sys_getgroups:
    return gdb_sys_getgroups;

  case aarch64_sys_setgroups:
    return gdb_sys_setgroups;

  case aarch64_sys_setresuid:
    return gdb_sys_setresuid;

  case aarch64_sys_getresuid:
    return gdb_sys_getresuid;

  case aarch64_sys_setresgid:
    return gdb_sys_setresgid;

  case aarch64_sys_getresgid:
    return gdb_sys_getresgid;

  case aarch64_sys_getpgid:
    return gdb_sys_getpgid;

  case aarch64_sys_setfsuid:
    return gdb_sys_setfsuid;

  case aarch64_sys_setfsgid:
    return gdb_sys_setfsgid;

  case aarch64_sys_getsid:
    return gdb_sys_getsid;

  case aarch64_sys_capget:
    return gdb_sys_capget;

  case aarch64_sys_capset:
    return gdb_sys_capset;

  case aarch64_sys_rt_sigpending:
    return gdb_sys_rt_sigpending;

  case aarch64_sys_rt_sigtimedwait:
    return gdb_sys_rt_sigtimedwait;

  case aarch64_sys_rt_sigqueueinfo:
    return gdb_sys_rt_sigqueueinfo;

  case aarch64_sys_rt_sigsuspend:
    return gdb_sys_rt_sigsuspend;

  case aarch64_sys_sigaltstack:
    return gdb_sys_sigaltstack;

  case aarch64_sys_mknod:
    return gdb_sys_mknod;

  case aarch64_sys_personality:
    return gdb_sys_personality;

  case aarch64_sys_statfs:
    return gdb_sys_statfs;

  case aarch64_sys_fstat:
    return gdb_sys_fstat;

  case aarch64_sys_fstatfs:
    return gdb_sys_fstatfs;

  case aarch64_sys_getpriority:
    return gdb_sys_getpriority;

  case aarch64_sys_setpriority:
    return gdb_sys_setpriority;

  case aarch64_sys_sched_setparam:
    return gdb_sys_sched_setparam;

  case aarch64_sys_sched_getparam:
    return gdb_sys_sched_getparam;

  case aarch64_sys_sched_setscheduler:
    return gdb_sys_sched_setscheduler;

  case aarch64_sys_sched_getscheduler:
    return gdb_sys_sched_getscheduler;

  case aarch64_sys_sched_get_priority_max:
    return gdb_sys_sched_get_priority_max;

  case aarch64_sys_sched_get_priority_min:
    return gdb_sys_sched_get_priority_min;

  case aarch64_sys_sched_rr_get_interval:
    return gdb_sys_sched_rr_get_interval;

  case aarch64_sys_mlock:
    return gdb_sys_mlock;

  case aarch64_sys_munlock:
    return gdb_sys_munlock;

  case aarch64_sys_mlockall:
    return gdb_sys_mlockall;

  case aarch64_sys_munlockall:
    return gdb_sys_munlockall;

  case aarch64_sys_vhangup:
    return gdb_sys_vhangup;

  case aarch64_sys_prctl:
    return gdb_sys_prctl;

  case aarch64_sys_adjtimex:
    return gdb_sys_adjtimex;

  case aarch64_sys_setrlimit:
    return gdb_sys_setrlimit;

  case aarch64_sys_chroot:
    return gdb_sys_chroot;

  case aarch64_sys_sync:
    return gdb_sys_sync;

  case aarch64_sys_acct:
    return gdb_sys_acct;

  case aarch64_sys_settimeofday:
    return gdb_sys_settimeofday;

  case aarch64_sys_mount:
    return gdb_sys_mount;

  case aarch64_sys_swapon:
    return gdb_sys_swapon;

  case aarch64_sys_swapoff:
    return gdb_sys_swapoff;

  case aarch64_sys_reboot:
    return gdb_sys_reboot;

  case aarch64_sys_sethostname:
    return gdb_sys_sethostname;

  case aarch64_sys_setdomainname:
    return gdb_sys_setdomainname;

  case aarch64_sys_init_module:
    return gdb_sys_init_module;

  case aarch64_sys_delete_module:
    return gdb_sys_delete_module;

  case aarch64_sys_quotactl:
    return gdb_sys_quotactl;

  case aarch64_sys_nfsservctl:
    return gdb_sys_nfsservctl;

  case aarch64_sys_gettid:
    return gdb_sys_gettid;

  case aarch64_sys_readahead:
    return gdb_sys_readahead;

  case aarch64_sys_setxattr:
    return gdb_sys_setxattr;

  case aarch64_sys_lsetxattr:
    return gdb_sys_lsetxattr;

  case aarch64_sys_fsetxattr:
    return gdb_sys_fsetxattr;

  case aarch64_sys_getxattr:
    return gdb_sys_getxattr;

  case aarch64_sys_lgetxattr:
    return gdb_sys_lgetxattr;

  case aarch64_sys_fgetxattr:
    return gdb_sys_fgetxattr;

  case aarch64_sys_listxattr:
    return gdb_sys_listxattr;

  case aarch64_sys_llistxattr:
    return gdb_sys_llistxattr;

  case aarch64_sys_flistxattr:
    return gdb_sys_flistxattr;

  case aarch64_sys_removexattr:
    return gdb_sys_removexattr;

  case aarch64_sys_lremovexattr:
    return gdb_sys_lremovexattr;

  case aarch64_sys_fremovexattr:
    return gdb_sys_fremovexattr;

  case aarch64_sys_tkill:
    return gdb_sys_tkill;

  case aarch64_sys_times:
    return gdb_sys_times;

  case aarch64_sys_futex:
    return gdb_sys_futex;

  case aarch64_sys_sched_setaffinity:
    return gdb_sys_sched_setaffinity;

  case aarch64_sys_sched_getaffinity:
    return gdb_sys_sched_getaffinity;

  case aarch64_sys_io_setup:
    return gdb_sys_io_setup;

  case aarch64_sys_io_destroy:
    return gdb_sys_io_destroy;

  case aarch64_sys_io_getevents:
    return gdb_sys_io_getevents;

  case aarch64_sys_io_submit:
    return gdb_sys_io_submit;

  case aarch64_sys_io_cancel:
    return gdb_sys_io_cancel;

  case aarch64_sys_lookup_dcookie:
    return gdb_sys_lookup_dcookie;

  case aarch64_sys_epoll_create1:
    return gdb_sys_epoll_create;

  case aarch64_sys_remap_file_pages:
    return gdb_sys_remap_file_pages;

  case aarch64_sys_getdents64:
    return gdb_sys_getdents64;

  case aarch64_sys_set_tid_address:
    return gdb_sys_set_tid_address;

  case aarch64_sys_semtimedop:
    return gdb_sys_semtimedop;

  case aarch64_sys_fadvise64:
    return gdb_sys_fadvise64;

  case aarch64_sys_timer_create:
    return gdb_sys_timer_create;

  case aarch64_sys_timer_settime:
    return gdb_sys_timer_settime;

  case aarch64_sys_timer_gettime:
    return gdb_sys_timer_gettime;

  case aarch64_sys_timer_getoverrun:
    return gdb_sys_timer_getoverrun;

  case aarch64_sys_timer_delete:
    return gdb_sys_timer_delete;

  case aarch64_sys_clock_settime:
    return gdb_sys_clock_settime;

  case aarch64_sys_clock_gettime:
    return gdb_sys_clock_gettime;

  case aarch64_sys_clock_getres:
    return gdb_sys_clock_getres;

  case aarch64_sys_clock_nanosleep:
    return gdb_sys_clock_nanosleep;

  case aarch64_sys_exit_group:
    return gdb_sys_exit_group;

  case aarch64_sys_epoll_pwait:
    return gdb_sys_epoll_pwait;

  case aarch64_sys_epoll_ctl:
    return gdb_sys_epoll_ctl;

  case aarch64_sys_tgkill:
    return gdb_sys_tgkill;

  case aarch64_sys_mbind:
    return gdb_sys_mbind;

  case aarch64_sys_set_mempolicy:
    return gdb_sys_set_mempolicy;

  case aarch64_sys_get_mempolicy:
    return gdb_sys_get_mempolicy;

  case aarch64_sys_mq_open:
    return gdb_sys_mq_open;

  case aarch64_sys_mq_unlink:
    return gdb_sys_mq_unlink;

  case aarch64_sys_mq_timedsend:
    return gdb_sys_mq_timedsend;

  case aarch64_sys_mq_timedreceive:
    return gdb_sys_mq_timedreceive;

  case aarch64_sys_mq_notify:
    return gdb_sys_mq_notify;

  case aarch64_sys_mq_getsetattr:
    return gdb_sys_mq_getsetattr;

  case aarch64_sys_kexec_load:
    return gdb_sys_kexec_load;

  case aarch64_sys_waitid:
    return gdb_sys_waitid;

  case aarch64_sys_add_key:
    return gdb_sys_add_key;

  case aarch64_sys_request_key:
    return gdb_sys_request_key;

  case aarch64_sys_keyctl:
    return gdb_sys_keyctl;

  case aarch64_sys_ioprio_set:
    return gdb_sys_ioprio_set;

  case aarch64_sys_ioprio_get:
    return gdb_sys_ioprio_get;

  case aarch64_sys_inotify_add_watch:
    return gdb_sys_inotify_add_watch;

  case aarch64_sys_inotify_rm_watch:
    return gdb_sys_inotify_rm_watch;

  case aarch64_sys_migrate_pages:
    return gdb_sys_migrate_pages;

  case aarch64_sys_pselect6:
    return gdb_sys_pselect6;

  case aarch64_sys_ppoll:
    return gdb_sys_ppoll;

  case aarch64_sys_unshare:
    return gdb_sys_unshare;

  case aarch64_sys_set_robust_list:
    return gdb_sys_set_robust_list;

  case aarch64_sys_get_robust_list:
    return gdb_sys_get_robust_list;

  case aarch64_sys_splice:
    return gdb_sys_splice;

  case aarch64_sys_tee:
    return gdb_sys_tee;

  case aarch64_sys_sync_file_range:
    return gdb_sys_sync_file_range;

  case aarch64_sys_vmsplice:
    return gdb_sys_vmsplice;

  case aarch64_sys_move_pages:
    return gdb_sys_move_pages;

  case aarch64_sys_mmap:
    return gdb_sys_mmap2;

  default:
    return -1;
  }
}

/* Record all registers but PC register for process-record.  */

static int
aarch64_all_but_pc_registers_record (struct regcache *regcache)
{
  int i;

  for (i = 0; i < AARCH64_PC_REGNUM; i++)
    if (record_full_arch_list_add_reg (regcache, AARCH64_X0_REGNUM + i))
      return -1;

  if (record_full_arch_list_add_reg (regcache, AARCH64_CPSR_REGNUM))
    return -1;

  return 0;
}

/* Handler for arm system call instruction recording.  */

static int
aarch64_linux_syscall_record (struct regcache *regcache, unsigned long svc_number)
{
  int ret = 0;
  enum gdb_syscall syscall_gdb;

  syscall_gdb = aarch64_canonicalize_syscall (svc_number);

  if (syscall_gdb < 0)
    {
      printf_unfiltered (_("Process record and replay target doesn't "
                           "support syscall number %s\n"),
                           plongest (svc_number));
      return -1;
    }

  if (syscall_gdb == gdb_sys_sigreturn
      || syscall_gdb == gdb_sys_rt_sigreturn)
   {
     if (aarch64_all_but_pc_registers_record (regcache))
       return -1;
     return 0;
   }

  ret = record_linux_system_call (syscall_gdb, regcache,
                                  &aarch64_linux_record_tdep);
  if (ret != 0)
    return ret;

  /* Record the return value of the system call.  */
  if (record_full_arch_list_add_reg (regcache, AARCH64_X0_REGNUM))
    return -1;
  /* Record LR.  */
  if (record_full_arch_list_add_reg (regcache, AARCH64_LR_REGNUM))
    return -1;
  /* Record CPSR.  */
  if (record_full_arch_list_add_reg (regcache, AARCH64_CPSR_REGNUM))
    return -1;

  return 0;
}

static void
aarch64_linux_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  static const char *const stap_integer_prefixes[] = { "#", "", NULL };
  static const char *const stap_register_prefixes[] = { "", NULL };
  static const char *const stap_register_indirection_prefixes[] = { "[",
								    NULL };
  static const char *const stap_register_indirection_suffixes[] = { "]",
								    NULL };
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  tdep->lowest_pc = 0x8000;

  linux_init_abi (info, gdbarch);

  set_solib_svr4_fetch_link_map_offsets (gdbarch,
					 svr4_lp64_fetch_link_map_offsets);

  /* Enable TLS support.  */
  set_gdbarch_fetch_tls_load_module_address (gdbarch,
                                             svr4_fetch_objfile_link_map);

  /* Shared library handling.  */
  set_gdbarch_skip_trampoline_code (gdbarch, find_solib_trampoline_target);

  set_gdbarch_get_siginfo_type (gdbarch, linux_get_siginfo_type);
  tramp_frame_prepend_unwinder (gdbarch, &aarch64_linux_rt_sigframe);

  /* Enable longjmp.  */
  tdep->jb_pc = 11;

  set_gdbarch_iterate_over_regset_sections
    (gdbarch, aarch64_linux_iterate_over_regset_sections);

  /* SystemTap related.  */
  set_gdbarch_stap_integer_prefixes (gdbarch, stap_integer_prefixes);
  set_gdbarch_stap_register_prefixes (gdbarch, stap_register_prefixes);
  set_gdbarch_stap_register_indirection_prefixes (gdbarch,
					    stap_register_indirection_prefixes);
  set_gdbarch_stap_register_indirection_suffixes (gdbarch,
					    stap_register_indirection_suffixes);
  set_gdbarch_stap_is_single_operand (gdbarch, aarch64_stap_is_single_operand);
  set_gdbarch_stap_parse_special_token (gdbarch,
					aarch64_stap_parse_special_token);

  /* Reversible debugging, process record.  */
  set_gdbarch_process_record (gdbarch, aarch64_process_record);
  /* Syscall record.  */
  tdep->aarch64_syscall_record = aarch64_linux_syscall_record;

  /* Initialize the aarch64_linux_record_tdep.  */
  /* These values are the size of the type that will be used in a system
     call.  They are obtained from Linux Kernel source.  */
  aarch64_linux_record_tdep.size_pointer
    = gdbarch_ptr_bit (gdbarch) / TARGET_CHAR_BIT;
  aarch64_linux_record_tdep.size__old_kernel_stat = 32;
  aarch64_linux_record_tdep.size_tms = 32;
  aarch64_linux_record_tdep.size_loff_t = 8;
  aarch64_linux_record_tdep.size_flock = 32;
  aarch64_linux_record_tdep.size_oldold_utsname = 45;
  aarch64_linux_record_tdep.size_ustat = 32;
  aarch64_linux_record_tdep.size_old_sigaction = 152;
  aarch64_linux_record_tdep.size_old_sigset_t = 128;
  aarch64_linux_record_tdep.size_rlimit = 16;
  aarch64_linux_record_tdep.size_rusage = 144;
  aarch64_linux_record_tdep.size_timeval = 16;
  aarch64_linux_record_tdep.size_timezone = 8;
  aarch64_linux_record_tdep.size_old_gid_t = 2;
  aarch64_linux_record_tdep.size_old_uid_t = 2;
  aarch64_linux_record_tdep.size_fd_set = 128;
  aarch64_linux_record_tdep.size_dirent = 280;
  aarch64_linux_record_tdep.size_dirent64 = 280;
  aarch64_linux_record_tdep.size_statfs = 120;
  aarch64_linux_record_tdep.size_statfs64 = 120;
  aarch64_linux_record_tdep.size_sockaddr = 16;
  aarch64_linux_record_tdep.size_int
    = gdbarch_int_bit (gdbarch) / TARGET_CHAR_BIT;
  aarch64_linux_record_tdep.size_long
    = gdbarch_long_bit (gdbarch) / TARGET_CHAR_BIT;
  aarch64_linux_record_tdep.size_ulong
    = gdbarch_long_bit (gdbarch) / TARGET_CHAR_BIT;
  aarch64_linux_record_tdep.size_msghdr = 56;
  aarch64_linux_record_tdep.size_itimerval = 32;
  aarch64_linux_record_tdep.size_stat = 144;
  aarch64_linux_record_tdep.size_old_utsname = 325;
  aarch64_linux_record_tdep.size_sysinfo = 112;
  aarch64_linux_record_tdep.size_msqid_ds = 120;
  aarch64_linux_record_tdep.size_shmid_ds = 112;
  aarch64_linux_record_tdep.size_new_utsname = 390;
  aarch64_linux_record_tdep.size_timex = 208;
  aarch64_linux_record_tdep.size_mem_dqinfo = 24;
  aarch64_linux_record_tdep.size_if_dqblk = 72;
  aarch64_linux_record_tdep.size_fs_quota_stat = 80;
  aarch64_linux_record_tdep.size_timespec = 16;
  aarch64_linux_record_tdep.size_pollfd = 8;
  aarch64_linux_record_tdep.size_NFS_FHSIZE = 32;
  aarch64_linux_record_tdep.size_knfsd_fh = 132;
  aarch64_linux_record_tdep.size_TASK_COMM_LEN = 16;
  aarch64_linux_record_tdep.size_sigaction = 152;
  aarch64_linux_record_tdep.size_sigset_t = 128;
  aarch64_linux_record_tdep.size_siginfo_t = 128;
  aarch64_linux_record_tdep.size_cap_user_data_t = 8;
  aarch64_linux_record_tdep.size_stack_t = 24;
  aarch64_linux_record_tdep.size_off_t = 8;
  aarch64_linux_record_tdep.size_stat64 = 144;
  aarch64_linux_record_tdep.size_gid_t = 4;
  aarch64_linux_record_tdep.size_uid_t = 4;
  aarch64_linux_record_tdep.size_PAGE_SIZE = 4096;
  aarch64_linux_record_tdep.size_flock64 = 32;
  aarch64_linux_record_tdep.size_user_desc = 16;
  aarch64_linux_record_tdep.size_io_event = 32;
  aarch64_linux_record_tdep.size_iocb = 64;
  aarch64_linux_record_tdep.size_epoll_event = 12;
  aarch64_linux_record_tdep.size_itimerspec = 32;
  aarch64_linux_record_tdep.size_mq_attr = 64;
  aarch64_linux_record_tdep.size_siginfo = 128;
  aarch64_linux_record_tdep.size_termios = 60;
  aarch64_linux_record_tdep.size_termios2 = 44;
  aarch64_linux_record_tdep.size_pid_t = 4;
  aarch64_linux_record_tdep.size_winsize = 8;
  aarch64_linux_record_tdep.size_serial_struct = 72;
  aarch64_linux_record_tdep.size_serial_icounter_struct = 80;
  aarch64_linux_record_tdep.size_hayes_esp_config = 12;
  aarch64_linux_record_tdep.size_size_t = 8;
  aarch64_linux_record_tdep.size_iovec = 16;

  /* These values are the second argument of system call "sys_ioctl".
     They are obtained from Linux Kernel source.  */
  aarch64_linux_record_tdep.ioctl_TCGETS = 0x5401;
  aarch64_linux_record_tdep.ioctl_TCSETS = 0x5402;
  aarch64_linux_record_tdep.ioctl_TCSETSW = 0x5403;
  aarch64_linux_record_tdep.ioctl_TCSETSF = 0x5404;
  aarch64_linux_record_tdep.ioctl_TCGETA = 0x5405;
  aarch64_linux_record_tdep.ioctl_TCSETA = 0x5406;
  aarch64_linux_record_tdep.ioctl_TCSETAW = 0x5407;
  aarch64_linux_record_tdep.ioctl_TCSETAF = 0x5408;
  aarch64_linux_record_tdep.ioctl_TCSBRK = 0x5409;
  aarch64_linux_record_tdep.ioctl_TCXONC = 0x540a;
  aarch64_linux_record_tdep.ioctl_TCFLSH = 0x540b;
  aarch64_linux_record_tdep.ioctl_TIOCEXCL = 0x540c;
  aarch64_linux_record_tdep.ioctl_TIOCNXCL = 0x540d;
  aarch64_linux_record_tdep.ioctl_TIOCSCTTY = 0x540e;
  aarch64_linux_record_tdep.ioctl_TIOCGPGRP = 0x540f;
  aarch64_linux_record_tdep.ioctl_TIOCSPGRP = 0x5410;
  aarch64_linux_record_tdep.ioctl_TIOCOUTQ = 0x5411;
  aarch64_linux_record_tdep.ioctl_TIOCSTI = 0x5412;
  aarch64_linux_record_tdep.ioctl_TIOCGWINSZ = 0x5413;
  aarch64_linux_record_tdep.ioctl_TIOCSWINSZ = 0x5414;
  aarch64_linux_record_tdep.ioctl_TIOCMGET = 0x5415;
  aarch64_linux_record_tdep.ioctl_TIOCMBIS = 0x5416;
  aarch64_linux_record_tdep.ioctl_TIOCMBIC = 0x5417;
  aarch64_linux_record_tdep.ioctl_TIOCMSET = 0x5418;
  aarch64_linux_record_tdep.ioctl_TIOCGSOFTCAR = 0x5419;
  aarch64_linux_record_tdep.ioctl_TIOCSSOFTCAR = 0x541a;
  aarch64_linux_record_tdep.ioctl_FIONREAD = 0x541b;
  aarch64_linux_record_tdep.ioctl_TIOCINQ = 0x541b;
  aarch64_linux_record_tdep.ioctl_TIOCLINUX = 0x541c;
  aarch64_linux_record_tdep.ioctl_TIOCCONS = 0x541d;
  aarch64_linux_record_tdep.ioctl_TIOCGSERIAL = 0x541e;
  aarch64_linux_record_tdep.ioctl_TIOCSSERIAL = 0x541f;
  aarch64_linux_record_tdep.ioctl_TIOCPKT = 0x5420;
  aarch64_linux_record_tdep.ioctl_FIONBIO = 0x5421;
  aarch64_linux_record_tdep.ioctl_TIOCNOTTY = 0x5422;
  aarch64_linux_record_tdep.ioctl_TIOCSETD = 0x5423;
  aarch64_linux_record_tdep.ioctl_TIOCGETD = 0x5424;
  aarch64_linux_record_tdep.ioctl_TCSBRKP = 0x5425;
  aarch64_linux_record_tdep.ioctl_TIOCTTYGSTRUCT = 0x5426;
  aarch64_linux_record_tdep.ioctl_TIOCSBRK = 0x5427;
  aarch64_linux_record_tdep.ioctl_TIOCCBRK = 0x5428;
  aarch64_linux_record_tdep.ioctl_TIOCGSID = 0x5429;
  aarch64_linux_record_tdep.ioctl_TCGETS2 = 0x802c542a;
  aarch64_linux_record_tdep.ioctl_TCSETS2 = 0x402c542b;
  aarch64_linux_record_tdep.ioctl_TCSETSW2 = 0x402c542c;
  aarch64_linux_record_tdep.ioctl_TCSETSF2 = 0x402c542d;
  aarch64_linux_record_tdep.ioctl_TIOCGPTN = 0x80045430;
  aarch64_linux_record_tdep.ioctl_TIOCSPTLCK = 0x40045431;
  aarch64_linux_record_tdep.ioctl_FIONCLEX = 0x5450;
  aarch64_linux_record_tdep.ioctl_FIOCLEX = 0x5451;
  aarch64_linux_record_tdep.ioctl_FIOASYNC = 0x5452;
  aarch64_linux_record_tdep.ioctl_TIOCSERCONFIG = 0x5453;
  aarch64_linux_record_tdep.ioctl_TIOCSERGWILD = 0x5454;
  aarch64_linux_record_tdep.ioctl_TIOCSERSWILD = 0x5455;
  aarch64_linux_record_tdep.ioctl_TIOCGLCKTRMIOS = 0x5456;
  aarch64_linux_record_tdep.ioctl_TIOCSLCKTRMIOS = 0x5457;
  aarch64_linux_record_tdep.ioctl_TIOCSERGSTRUCT = 0x5458;
  aarch64_linux_record_tdep.ioctl_TIOCSERGETLSR = 0x5459;
  aarch64_linux_record_tdep.ioctl_TIOCSERGETMULTI = 0x545a;
  aarch64_linux_record_tdep.ioctl_TIOCSERSETMULTI = 0x545b;
  aarch64_linux_record_tdep.ioctl_TIOCMIWAIT = 0x545c;
  aarch64_linux_record_tdep.ioctl_TIOCGICOUNT = 0x545d;
  aarch64_linux_record_tdep.ioctl_TIOCGHAYESESP = 0x545e;
  aarch64_linux_record_tdep.ioctl_TIOCSHAYESESP = 0x545f;
  aarch64_linux_record_tdep.ioctl_FIOQSIZE = 0x5460;

  /* These values are the second argument of system call "sys_fcntl"
     and "sys_fcntl64".  They are obtained from Linux Kernel source.  */
  aarch64_linux_record_tdep.fcntl_F_GETLK = 5;
  aarch64_linux_record_tdep.fcntl_F_GETLK64 = 12;
  aarch64_linux_record_tdep.fcntl_F_SETLK64 = 13;
  aarch64_linux_record_tdep.fcntl_F_SETLKW64 = 14;

  /* The AArch64 syscall calling convention: reg x0-x7 for arguments,
     reg x8 for syscall number and return value in reg x0.  */
  aarch64_linux_record_tdep.arg1 = AARCH64_X0_REGNUM + 0;
  aarch64_linux_record_tdep.arg2 = AARCH64_X0_REGNUM + 1;
  aarch64_linux_record_tdep.arg3 = AARCH64_X0_REGNUM + 2;
  aarch64_linux_record_tdep.arg4 = AARCH64_X0_REGNUM + 3;
  aarch64_linux_record_tdep.arg5 = AARCH64_X0_REGNUM + 4;
  aarch64_linux_record_tdep.arg6 = AARCH64_X0_REGNUM + 5;
  aarch64_linux_record_tdep.arg7 = AARCH64_X0_REGNUM + 6;
  aarch64_linux_record_tdep.arg8 = AARCH64_X0_REGNUM + 7;
}

/* Provide a prototype to silence -Wmissing-prototypes.  */
extern initialize_file_ftype _initialize_aarch64_linux_tdep;

void
_initialize_aarch64_linux_tdep (void)
{
  gdbarch_register_osabi (bfd_arch_aarch64, 0, GDB_OSABI_LINUX,
			  aarch64_linux_init_abi);
}
