/* tracepoint format structs.
 *
 * field names, types and sizes must match the actual tracepoint formats
 * (kernel 7.0.0-34-generic [6.18]; verified against the per-event format
 * files under /sys/kernel/tracing. sizes are the format's, which for the
 * syscall tracepoints means `long`-sized arguments).
 * nothing checks these layouts at load time: they are plain structs, not
 * BTF-relocated, so a drift would read the wrong offsets silently. on a new
 * kernel release, diff them against /sys/kernel/tracing/events/<cat>/<name>/
 * format before trusting the backend. verified on 6.18 (x86_64), where the
 * offsets match exactly.
 */
#ifndef DEPREHENDO_TP_DEFS_H
#define DEPREHENDO_TP_DEFS_H

/* sched:sched_process_exec: common + __data_loc filename + pid + old_pid */
struct tp_exec {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int filename; /* __data_loc char[]: id = (u32)loc & 0xffff → ctx + off */
	int pid;
	int old_pid;
};

/* sched:sched_process_exit: comm[16], pid, prio, group_dead */
struct tp_exit {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	char comm[16]; /* matches the format's `char comm[16]` */
	int pid;
	int prio;
	char group_dead; /* bool byte-size 1 in the format */
};

/* signal:signal_generate: sig, errno, code, comm[16], pid, group, result */
struct tp_signal_generate {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int sig;
	int errno;
	int code; /* siginfo.si_code */
	char comm[16];
	int pid; /* the task the signal was queued for */
	int group;
	int result; /* 0 queued, 1 ignored, 2 already pending, 3 overflow, 4 info lost */
};

/* oom:mark_victim: pid, __data_loc comm, plus RSS/uid fields we never
 * forward (§12 privacy: the OOM event's uid and RSS are dropped). */
struct tp_oom {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int pid;
	int comm; /* __data_loc char[] */
	unsigned long total_vm;
	unsigned long anon_rss;
	unsigned long file_rss;
	unsigned long shmem_rss;
	unsigned int uid;
	unsigned long pgtables;
	short oom_score_adj;
};

/* one shared struct for the sys-enter tracepoints we use. the syscall
 * tracepoint formats declare their arguments as `pid_t`/`int` but size them
 * 8 (syscall args are long). field *names* differ per syscall and libbpf
 * matches by name, so we define one struct per syscall even where the
 * layouts coincide:
 *
 *   sys_enter_kill:           pid, sig
 *   sys_enter_tkill:          pid, sig
 *   sys_enter_tgkill:         tgid, pid, sig
 *   sys_enter_rt_sigqueueinfo:    pid, sig, uinfo
 *   sys_enter_rt_tgsigqueueinfo:  tgid, pid, sig, uinfo
 *   sys_enter_pidfd_send_signal:  pidfd, sig, info, flags
 *   sys_exit_*:               ret
 */
struct tp_sys_enter_kill {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	long pid;
	long sig;
};

struct tp_sys_enter_tkill {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	long pid;
	long sig;
};

struct tp_sys_enter_tgkill {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	long tgid;
	long pid;
	long sig;
};

struct tp_sys_enter_rt_sigqueueinfo {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	long pid;
	long sig;
	long uinfo;
};

struct tp_sys_enter_rt_tgsigqueueinfo {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	long tgid;
	long pid;
	long sig;
	long uinfo;
};

struct tp_sys_enter_pidfd_send_signal {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	long pidfd;
	long sig;
	long info;
	long flags;
};

struct tp_sys_exit {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	long ret;
};

#endif /* DEPREHENDO_TP_DEFS_H */
