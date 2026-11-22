// runopsy-trace eBPF backend (contract §2, engineering queue item 4).
//
// primary backend: tracepoints + one raw tracepoint sched_process_fork (it
// hands us the parent/child task_struct pointers, which the pretty
// tracepoint does not, so identity stays exact per §4). events reach user
// space through a ring buffer; user space stamps sequence numbers and
// publishes through the same bounded pipeline as the proc connector, so
// loss semantics cannot diverge between backends.
//
// attach points (all present on 6.18; contract §2.3):
//   EXEC   sched:sched_process_exec
//   EXIT   sched:sched_process_exit (group_dead)
//   fork   raw sched_process_fork (watch inheritance)
//   SENT   sys_enter/exit_{kill,tkill,tgkill,rt_sigqueueinfo,
//                          rt_tgsigqueueinfo,pidfd_send_signal}
//   GEN    signal:signal_generate (stop confirmation + resume, rule 1)
//   OOM    oom:mark_victim
//
// kernel floor: 5.8 (ring buffer). uses bpf_get_current_task_btf (5.11) and
// bpf_task_from_pid (5.15); the backend availability check enforces 5.15
// and says so. identity: start_ticks = start_boottime_ns / 10^7 (§4, USER_HZ
// 100) equals /proc/<pid>/stat field 22 and CoRe-stamped in-kernel.
//
// privacy (§12): only the fields the schema carries. argv/env/uid/RSS are
// never read into the ring buffer.
//
// the watch map is identity-aware (§6.3 f): key tgid → expected
// start_ticks, where 0 means "any identity" (an agent that could not
// resolve it). A lookup whose ticks mismatch deletes the stale entry and
// declines: a recycled PID must never adopt a dead process's watch
// (STALE_IDENTITY), enforced here in-kernel as well as at the control.

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "tp_defs.h"

char LICENSE[] SEC("license") = "GPL";

// ---- constants mirrored by the rust side ----------------------------------

#define REC_EXEC    1
#define REC_EXIT    2
#define REC_FORK    3
#define REC_SENT    4
#define REC_STOP    5
#define REC_RESUME  6
#define REC_OOM     7

// siginfo si_codes that keep a kernel-queued signal attributable to the
// syscall `current` was in (contract §3.3 rule 1).
#define SI_USER   0
#define SI_QUEUE  -1
#define SI_TKILL  -6

#define SIGCHLD 17
#define SIGCONT 18

#define CLD_STOPPED 5
#define CLD_CONTINUED 6

#define USER_HZ 100
#define NS_PER_TICK (1000000000ULL / USER_HZ)

#define PATH_MAX_BPF 512
#define WATCH_MAX 4096

// kernel 6.18 dropped both signal_struct->pgrp and the numeric pid field on
// struct pid: the group pid number is pids[PIDTYPE_PGID]->numbers[0].nr
// (enum pid_type: PID=0, TGID=1, PGID=2, SID=3; struct upid.nr is int).
#define PIDS_PGID 2

// ---- maps -----------------------------------------------------------------

struct rec {
	u64 ts;
	u32 kind;
	u32 pid;       // subject tgid
	u32 ppid;      // subject's parent tgid
	u32 pgid;      // subject's pgid (or the addressed pgid for group sent)
	u32 other_pid; // FORK child tgid / SENT sender tgid, else 0
	u32 sig;
	u32 fact;      // 1 SENT, 2 EXITED_BY_SIGNAL, 3 OBSERVED_STOP
	u32 flags;     // bit0 status present, bit1 group-addressed sent
	s64 status;    // EXIT: the wait status as the parent would see it
	s64 start_ticks;
	s64 other_start_ticks;
	s64 send_result;   // SENT: syscall return value
	char path[PATH_MAX_BPF]; // EXEC filename; OOM comm (informational)
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 21); // 2 MiB
} rb SEC(".maps");

// watched subjects: tgid → start_ticks (0 = any identity).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, WATCH_MAX);
	__type(key, u32);
	__type(value, u64);
} watched SEC(".maps");

// confirmed job-control stops: tgid → start_ticks. inserted on
// CLD_STOPPED confirmation, consumed by SIGCONT resume or group exit.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, WATCH_MAX);
	__type(key, u32);
	__type(value, u64);
} stopped SEC(".maps");

// loss counters the pump drains into the wire LOSS stage vocabulary:
//   [LOSS_RING]       ring-buffer reserve failures (KERNEL stage, 6.25);
//   [LOSS_WATCH_FULL] fork inheritance refused by a full watch map, so the
//                     child's subtree is unobserved (WATCH_FULL stage).
// neither is readable from user space otherwise, so the pump polls the array.
#define LOSS_RING       0
#define LOSS_WATCH_FULL 1
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, u64);
} loss_kernel SEC(".maps");

// debug counters (bpftool diagnosis during live runs; never exported on
// the wire): STAT_FORK_SEEN/WATCHED, EXEC_SEEN/WATCHED, EXIT_SEEN/WATCHED,
// SENT_SEEN/WATCHED.
#define STAT_FORK_SEEN     0
#define STAT_FORK_WATCHED  1
#define STAT_EXEC_SEEN     2
#define STAT_EXEC_WATCHED  3
#define STAT_EXIT_SEEN     4
#define STAT_EXIT_WATCHED  5
#define STAT_SENT_SEEN     6
#define STAT_SENT_WATCHED  7
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	__type(key, u32);
	__type(value, u64);
} stats SEC(".maps");

static __always_inline void bump_stat(u32 k)
{
	u64 *v = bpf_map_lookup_elem(&stats, &k);
	if (v)
		__sync_fetch_and_add(v, 1);
}

// one pending send per sending thread: set at sys_enter_*, marked for
// emission when a generate with an attributable si_code happens inside the
// window, emitted once with the syscall return at sys_exit_*.
// addressing modes (§3.3 SIGNAL_SENT "address A"). the mode is explicit:
// a sentinel value in `target` would collide with a real `kill(-N)`.
#define SEND_MODE_NUMERIC 0 // target is the syscall's pid operand
#define SEND_MODE_PIDFD   1 // pidfd_send_signal: target comes from generation

struct send_pending {
	u32 sender_tgid;
	s64 sender_ticks;
	s64 target;    // NUMERIC: >0 pid, -1 everything, < -1 -pgid, 0 own group
	s64 sender_pgid;  // resolved at enter for target==0
	int sig;
	int emit;      // rule-1 marked by the generate handler
	int mode;      // SEND_MODE_*
	u32 gen_pid;   // first attributable generation's recipient (tid)
};

// REC flags (struct rec.flags).
#define FLAG_STATUS     1 // EXIT: status present
#define FLAG_GROUP      2 // SENT: addressed a process group (pgid set)
#define FLAG_BROADCAST  4 // SENT: kill(-1), everything the sender may signal

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct send_pending);
} sendp SEC(".maps");

// ---- helpers --------------------------------------------------------------

static __always_inline int bump_loss(u32 k)
{
	u64 *v = bpf_map_lookup_elem(&loss_kernel, &k);
	if (v)
		__sync_fetch_and_add(v, 1);
	return 0;
}

static __always_inline int bump_kernel_loss()
{
	return bump_loss(LOSS_RING);
}

static __always_inline s64 ticks_of(struct task_struct *t)
{
	if (!t)
		return 0;
	u64 boot_ns = BPF_CORE_READ(t, start_boottime);
	return (s64)(boot_ns / NS_PER_TICK);
}

// §6.3 f in kernel: watched holds (tgid → ticks). A mismatch is a recycled
// PID: remove the stale entry, never adopt it.
static __always_inline int is_watched(u32 tgid, s64 ticks)
{
	if (!tgid)
		return 0;
	u64 *want = bpf_map_lookup_elem(&watched, &tgid);
	if (!want)
		return 0;
	if (*want != 0 && ticks != 0 && *want != (u64)ticks) {
		bpf_map_delete_elem(&watched, &tgid);
		return 0;
	}
	return 1;
}

static __always_inline struct rec *reserve_rec()
{
	struct rec *r = bpf_ringbuf_reserve(&rb, sizeof(*r), 0);
	if (!r)
		bump_kernel_loss();
	return r;
}

static __always_inline void fill_common(struct rec *r, u32 kind)
{
	__builtin_memset(r, 0, sizeof(*r));
	r->ts = bpf_ktime_get_ns();
	r->kind = kind;
}

static __always_inline void fill_task_identity(struct task_struct *t, u32 tgid, struct rec *r)
{
	struct task_struct *gl = BPF_CORE_READ(t, group_leader);
	if (tgid == 0)
		tgid = BPF_CORE_READ(t, tgid);
	r->pid = tgid;
	r->ppid = BPF_CORE_READ(gl, real_parent, tgid);
	r->pgid = BPF_CORE_READ(gl, signal, pids[PIDS_PGID], numbers[0].nr);
	r->start_ticks = ticks_of(gl);
}

// resolve a task identity from a numeric pid/tid for SENT targets. returns
// via out-params tgid and ticks; 0 ticks means the identity could not be
// established ("unknown, never matched as if known", §4).
static __always_inline int resolve_task(u32 pid, u32 *out_tgid, s64 *out_ticks)
{
	*out_tgid = 0;
	*out_ticks = 0;
	if (!pid)
		return 0;
	struct task_struct *t = bpf_task_from_pid(pid);
	if (!t)
		return 0;
	u32 tgid = BPF_CORE_READ(t, tgid);
	struct task_struct *gl = BPF_CORE_READ(t, group_leader);
	*out_tgid = tgid;
	*out_ticks = ticks_of(gl);
	bpf_task_release(t);
	return tgid ? 1 : 0;
}

// ---- EXEC ------------------------------------------------------------------

SEC("tracepoint/sched/sched_process_exec")
int tp_exec(struct tp_exec *ctx)
{
	bump_stat(STAT_EXEC_SEEN);
	struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
	struct task_struct *gl = BPF_CORE_READ(t, group_leader);
	u32 tgid = BPF_CORE_READ(t, tgid);
	s64 ticks = ticks_of(gl);
	if (!is_watched(tgid, ticks))
		return 0;
	bump_stat(STAT_EXEC_WATCHED);

	struct rec *r = reserve_rec();
	if (!r)
		return 0;
	fill_common(r, REC_EXEC);
	fill_task_identity(t, tgid, r);
	// __data_loc filename: string lives at ctx + (loc & 0xffff).
	char *fname = (char *)ctx + ((u32)ctx->filename & 0xffff);
	bpf_probe_read_kernel_str(r->path, sizeof(r->path), fname);
	bpf_ringbuf_submit(r, 0);
	return 0;
}

// ---- EXIT ------------------------------------------------------------------
//
// one event per thread group (group_dead); a thread exit is never a process
// exit (§3.2). the termination signal comes only from the exit status of
// the leader as the parent's wait would see it: prefer the group-exit code
// recorded in signal_struct when the group died by signal, else the
// leader's own exit status. the exact bit composition is verified against a
// real kernel in the live tests (kill -TERM, kill -9, exit 0/7) before any
// consumer may rely on it.

SEC("tracepoint/sched/sched_process_exit")
int tp_exit(struct tp_exit *ctx)
{
	if (!ctx->group_dead)
		return 0;
	bump_stat(STAT_EXIT_SEEN);

	struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
	struct task_struct *gl = BPF_CORE_READ(t, group_leader);
	u32 tgid = BPF_CORE_READ(t, tgid);
	s64 ticks = ticks_of(gl);
	if (!is_watched(tgid, ticks))
		return 0;
	bump_stat(STAT_EXIT_WATCHED);

	struct rec *r = reserve_rec();
	if (!r)
		return 0;
	fill_common(r, REC_EXIT);
	fill_task_identity(t, tgid, r);
	r->flags |= FLAG_STATUS;
	// the leader's wait-status word. group_exit_code is set only when a
	// fatal signal started the group exit; otherwise fall back to the
	// leader's own status so a plain exit(7) stays exit(7).
	s64 gec = BPF_CORE_READ(gl, signal, group_exit_code);
	s64 ec = BPF_CORE_READ(gl, exit_code);
	r->status = gec ? gec : ec;
	bpf_ringbuf_submit(r, 0);

	bpf_map_delete_elem(&stopped, &tgid);
	bpf_map_delete_elem(&watched, &tgid); // the group is over
	return 0;
}

// ---- FORK (raw tracepoint: task pointers, §2.3) ----------------------------
//
// A child of a watched task becomes watched in-kernel immediately
// (inheritance, so a short-lived child's exec/exit is not missed before the
// next agent-driven sync), and a FORK record lets the pump add the child to
// the user-space set so later full syncs keep it.

SEC("raw_tp/sched_process_fork")
int raw_fork(void *raw_ctx)
{
	// the raw tracepoint context is the raw args array: sched_process_fork
	// is TP_PROTO(parent, child), so args[0]/args[1] are the two task_struct
	// pointers. (pointer arithmetic like `parent + 1` would be sizeof(task)
	// bytes past the parent, unrelated memory.)
	u64 *args = (u64 *)raw_ctx;
	struct task_struct *parent = (struct task_struct *)args[0];
	struct task_struct *child = (struct task_struct *)args[1];

	bump_stat(STAT_FORK_SEEN);
	u32 ptgid = BPF_CORE_READ(parent, tgid);
	s64 pticks = ticks_of(BPF_CORE_READ(parent, group_leader));
	if (!is_watched(ptgid, pticks))
		return 0;
	// only watchers inherit: a thread child (CLONE_THREAD) shares the
	// parent's tgid and is already watched; only a new group leader
	// creates a new subject.
	u32 ctgid = BPF_CORE_READ(child, tgid);
	if (ctgid == ptgid)
		return 0;
	s64 cticks = ticks_of(child);
	u64 want = (u64)cticks;
	// BPF_ANY: the child's exact identity replaces whatever the map holds
	// for that tgid. an "any identity" entry, or a stale one left by an
	// earlier process with the same PID, which would otherwise make every
	// later lookup for this child mismatch and silently drop its events.
	if (bpf_map_update_elem(&watched, &ctgid, &want, BPF_ANY) != 0) {
		// map full: the child's whole subtree is unobserved from here on.
		// counted so the pump reports WATCH_FULL loss (6.27: never silent).
		bump_loss(LOSS_WATCH_FULL);
		return 0;
	}
	bump_stat(STAT_FORK_WATCHED);

	struct rec *r = reserve_rec();
	if (!r)
		return 0;
	fill_common(r, REC_FORK);
	r->pid = ptgid;
	r->start_ticks = pticks;
	r->other_pid = ctgid;
	r->other_start_ticks = cticks;
	bpf_ringbuf_submit(r, 0);
	return 0;
}

// ---- SIGNAL_SENT (kill family) --------------------------------------------
//
// enter: record the sender and the addressed operand; generation inside the
// window with an attributable si_code marks it (rule 1); exit: emit once
// with the syscall return value. covering all five addressing modes of
// §3.3: kill(pid), tkill(tid), tgkill(tgid,tid), rt_sigqueueinfo(pid),
// rt_tgsigqueueinfo(tgid,tid), pidfd_send_signal(fd→pid in itself).

/* gate on the SENDER: a SENT fact is about a watched subject's own send
 * (§3.3). without the is_watched check, every kill-family syscall on the
 * host would stream through the ring buffer. the comment lives outside the
 * macro: empty lines / unterminated comments inside a #define body can't
 * survive cross-line splicing. */
#define SEND_ENTER_COMMON(targ, sig_arg, mode_arg) \
	struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf(); \
	struct task_struct *gl = BPF_CORE_READ(t, group_leader); \
	if (!is_watched(BPF_CORE_READ(t, tgid), ticks_of(gl))) \
		return 0; \
	struct send_pending p = {0}; \
	p.sender_tgid = BPF_CORE_READ(t, tgid); \
	p.sender_ticks = ticks_of(gl); \
	p.sender_pgid = BPF_CORE_READ(gl, signal, pids[PIDS_PGID], numbers[0].nr); \
	p.target = (targ); \
	p.sig = (int)(sig_arg); \
	p.mode = (mode_arg); \
	u32 tid = bpf_get_current_pid_tgid(); \
	bpf_map_update_elem(&sendp, &tid, &p, BPF_ANY);

SEC("tracepoint/syscalls/sys_enter_kill")
int tp_enter_kill(struct tp_sys_enter_kill *ctx)
{
	SEND_ENTER_COMMON(ctx->pid, ctx->sig, SEND_MODE_NUMERIC)
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_tkill")
int tp_enter_tkill(struct tp_sys_enter_tkill *ctx)
{
	SEND_ENTER_COMMON(ctx->pid, ctx->sig, SEND_MODE_NUMERIC)
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_tgkill")
int tp_enter_tgkill(struct tp_sys_enter_tgkill *ctx)
{
	SEND_ENTER_COMMON(ctx->pid, ctx->sig, SEND_MODE_NUMERIC)
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigqueueinfo")
int tp_enter_rt_sigqueueinfo(struct tp_sys_enter_rt_sigqueueinfo *ctx)
{
	SEND_ENTER_COMMON(ctx->pid, ctx->sig, SEND_MODE_NUMERIC)
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_tgsigqueueinfo")
int tp_enter_rt_tgsigqueueinfo(struct tp_sys_enter_rt_tgsigqueueinfo *ctx)
{
	SEND_ENTER_COMMON(ctx->pid, ctx->sig, SEND_MODE_NUMERIC)
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pidfd_send_signal")
int tp_enter_pidfd_send_signal(struct tp_sys_enter_pidfd_send_signal *ctx)
{
	// A pidfd names one process, but resolving fd → pid here would need
	// the file table. the recipient is taken from the attributable
	// generation instead (gen_pid), which is the process the kernel
	// actually queued the signal for.
	SEND_ENTER_COMMON(0, ctx->sig, SEND_MODE_PIDFD)
	return 0;
}

// Stop-marker values (map `stopped`): the subject's start_ticks while a
// confirmed stop is unresolved; RESUME_REPORTED once the SIGCONT path has
// already reported the resume, so the later CLD_CONTINUED does not repeat it.
#define RESUME_REPORTED ((u64)-1)

// emit a STOP or RESUME record for a watched subject task.
static __always_inline void emit_job_control(struct task_struct *t, u32 kind)
{
	struct rec *r = reserve_rec();
	if (!r)
		return;
	fill_common(r, kind);
	fill_task_identity(t, 0, r);
	if (kind == REC_STOP)
		r->fact = 3; // FACT_OBSERVED_STOP
	bpf_ringbuf_submit(r, 0);
}

// generate handler (rule 1 marking + stop/resume semantics, §3.3/§3.5).
//
// subject of a CLD_* SIGCHLD: the SIGCHLD is queued for the PARENT, so the
// tracepoint's `pid` field names the parent. the stopped/continued process
// is `current`. do_notify_parent_cldstop runs in its context (§3.1, fourth
// row; §3.5). reading `pid` reported the parent as stopped and lost every
// resume.
SEC("tracepoint/signal/signal_generate")
int tp_signal_generate(struct tp_signal_generate *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid = (u32)pid_tgid;

	if (ctx->sig == SIGCHLD &&
	    (ctx->code == CLD_STOPPED || ctx->code == CLD_CONTINUED)) {
		struct task_struct *cur = (struct task_struct *)bpf_get_current_task_btf();
		u32 stgid = BPF_CORE_READ(cur, tgid);
		s64 sticks = ticks_of(BPF_CORE_READ(cur, group_leader));
		if (is_watched(stgid, sticks)) {
			u64 *mark = bpf_map_lookup_elem(&stopped, &stgid);
			if (ctx->code == CLD_STOPPED) {
				// confirmed stop (§3.5).
				emit_job_control(cur, REC_STOP);
				u64 val = (u64)sticks;
				bpf_map_update_elem(&stopped, &stgid, &val, BPF_ANY);
			} else {
				// resume path 1 of 2 (§3.5). CLD_CONTINUED follows only a
				// real stop, so it is proof of a resume on its own; it is
				// suppressed only when the SIGCONT path already reported it.
				if (!mark || *mark != RESUME_REPORTED)
					emit_job_control(cur, REC_RESUME);
				bpf_map_delete_elem(&stopped, &stgid);
			}
		}
	}

	if (ctx->sig == SIGCONT) {
		// resume path 2 of 2 (§3.5): SIGCONT generated for a stopped
		// target, which is the recipient (`pid` is right here). whatever
		// the result field says, the resume happens (§3.3 rule 4), so
		// result is not consulted. the marker records that the resume was
		// reported, for the CLD_CONTINUED path above.
		struct task_struct *tk = bpf_task_from_pid((u32)ctx->pid);
		if (tk) {
			u32 stgid = BPF_CORE_READ(tk, tgid);
			s64 sticks = ticks_of(BPF_CORE_READ(tk, group_leader));
			u64 *mark = bpf_map_lookup_elem(&stopped, &stgid);
			if (mark && *mark != RESUME_REPORTED && is_watched(stgid, sticks)) {
				emit_job_control(tk, REC_RESUME);
				u64 done = RESUME_REPORTED;
				bpf_map_update_elem(&stopped, &stgid, &done, BPF_ANY);
			}
			bpf_task_release(tk);
		}
	}

	// Rule-1 marking: is `current` inside a kill-family syscall of its own?
	bump_stat(STAT_SENT_SEEN);
	struct send_pending *p = bpf_map_lookup_elem(&sendp, &tid);
	if (!p)
		return 0;
	if (ctx->code == SI_USER || ctx->code == SI_TKILL || ctx->code == SI_QUEUE) {
		if (!p->emit)
			p->gen_pid = (u32)ctx->pid; // the first recipient the kernel queued for
		p->emit = 1;
		p->sig = ctx->sig > 0 ? ctx->sig : p->sig;
	}
	return 0;
}

// exit handlers: emit the marked SENT event once, with the return value.
static void emit_sent(struct tp_sys_exit *ctx, struct send_pending *p)
{
	bump_stat(STAT_SENT_WATCHED);
	struct rec *r = reserve_rec();
	if (!r)
		return;
	fill_common(r, REC_SENT);
	r->sig = (u32)p->sig;
	r->send_result = ctx->ret;
	r->other_pid = p->sender_tgid;
	r->other_start_ticks = p->sender_ticks;

	// only sends that generated at least one attributable signal reach here
	// (p->emit), so a refused send (ESRCH, EPERM) is never reported as sent.
	// A partial group send can still return an error; it is carried in
	// send_result.
	s64 t = p->target;
	if (p->mode == SEND_MODE_PIDFD) {
		// the pidfd's process is the recipient the kernel queued for.
		u32 tgid = 0;
		s64 ticks = 0;
		resolve_task(p->gen_pid, &tgid, &ticks);
		r->pid = tgid ? tgid : p->gen_pid;
		r->start_ticks = ticks;
	} else if (t > 0) {
		u32 tgid = 0;
		s64 ticks = 0;
		resolve_task((u32)t, &tgid, &ticks);
		r->pid = tgid ? tgid : (u32)t;
		r->start_ticks = ticks;
	} else if (t == -1) {
		// kill(-1): every process the sender may signal (§3.3). there is
		// no group to name, so pid and pgid stay 0 rather than "pgid 1".
		r->flags |= FLAG_BROADCAST;
		r->pid = 0;
		r->pgid = 0;
	} else if (t < 0) {
		// group address: -pgid.
		r->flags |= FLAG_GROUP;
		r->pid = 0;
		r->pgid = (u32)(-t);
	} else {
		// 0: resolved to the sender's own process group at enter time.
		r->flags |= FLAG_GROUP;
		r->pid = 0;
		r->pgid = (u32)p->sender_pgid;
	}
	r->fact = 1; // FACT_SIGNAL_SENT
	bpf_ringbuf_submit(r, 0);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int tp_exit_kill(struct tp_sys_exit *ctx)
{
	u32 tid = bpf_get_current_pid_tgid();
	struct send_pending *p = bpf_map_lookup_elem(&sendp, &tid);
	if (p && p->emit)
		emit_sent(ctx, p);
	bpf_map_delete_elem(&sendp, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_tkill")
int tp_exit_tkill(struct tp_sys_exit *ctx)
{
	u32 tid = bpf_get_current_pid_tgid();
	struct send_pending *p = bpf_map_lookup_elem(&sendp, &tid);
	if (p && p->emit)
		emit_sent(ctx, p);
	bpf_map_delete_elem(&sendp, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_tgkill")
int tp_exit_tgkill(struct tp_sys_exit *ctx)
{
	u32 tid = bpf_get_current_pid_tgid();
	struct send_pending *p = bpf_map_lookup_elem(&sendp, &tid);
	if (p && p->emit)
		emit_sent(ctx, p);
	bpf_map_delete_elem(&sendp, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_rt_sigqueueinfo")
int tp_exit_rt_sigqueueinfo(struct tp_sys_exit *ctx)
{
	u32 tid = bpf_get_current_pid_tgid();
	struct send_pending *p = bpf_map_lookup_elem(&sendp, &tid);
	if (p && p->emit)
		emit_sent(ctx, p);
	bpf_map_delete_elem(&sendp, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_rt_tgsigqueueinfo")
int tp_exit_rt_tgsigqueueinfo(struct tp_sys_exit *ctx)
{
	u32 tid = bpf_get_current_pid_tgid();
	struct send_pending *p = bpf_map_lookup_elem(&sendp, &tid);
	if (p && p->emit)
		emit_sent(ctx, p);
	bpf_map_delete_elem(&sendp, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_pidfd_send_signal")
int tp_exit_pidfd_send_signal(struct tp_sys_exit *ctx)
{
	u32 tid = bpf_get_current_pid_tgid();
	struct send_pending *p = bpf_map_lookup_elem(&sendp, &tid);
	if (p && p->emit)
		emit_sent(ctx, p);
	bpf_map_delete_elem(&sendp, &tid);
	return 0;
}

// ---- OOM -------------------------------------------------------------------
//
// oom:mark_victim names the victim in its pid field; `current` is never the
// victim and never "the killer" (§3.6). the victim's identity is read from
// the victim task; uid/RSS are not loaded into the ring buffer at all.

SEC("tracepoint/oom/mark_victim")
int tp_oom(struct tp_oom *ctx)
{
	u32 victim = (u32)ctx->pid;
	if (!victim)
		return 0;

	struct rec *r = reserve_rec();
	if (!r)
		return 0;
	fill_common(r, REC_OOM);
	if (ctx->comm) {
		char *comm = (char *)ctx + ((u32)ctx->comm & 0xffff);
		bpf_probe_read_kernel_str(r->path, 16, comm);
	}
	resolve_task(victim, &r->pid, &r->start_ticks);
	if (!r->pid)
		r->pid = victim; // identity unresolvable: report the pid, ticks 0
	bpf_ringbuf_submit(r, 0);
	return 0;
}
