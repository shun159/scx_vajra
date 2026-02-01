#include "common.bpf.h"

char _license[] SEC("license") = "GPL";

/*
 * Specify a sibling CPU relationship for a specific scheduling domain.
 */
struct domain_arg {
	__s32 lvl_id;
	__s32 cpu_id;
	__s32 sibling_cpu_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u8);
} prio_cgroups SEC(".maps");

/*
 * Per-task local storage.
 */
struct task_ctx {
	struct bpf_cpumask __kptr *cpumask;
	struct bpf_cpumask __kptr *l2_cpumask;
	struct bpf_cpumask __kptr *llc_cpumask;

	bool is_high_prio;
	__u64 cgroup_id;

	__u64 nvcsw;
	__u64 nvcsw_ts;
	__u64 avg_nvcsw;
	__u64 avg_runtime;
	__u64 sum_runtime;
	__u64 last_run_at;
	__u64 deadline;
};

/* Map that contains task-local storage. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Per-CPU context.
 */
struct cpu_ctx {
	__u64 tot_runtime;
	__u64 prev_runtime;
	__u64 last_running;

	struct bpf_cpumask __kptr *smt_cpumask;
	struct bpf_cpumask __kptr *l2_cpumask;
	struct bpf_cpumask __kptr *llc_cpumask;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

/*
 * Return a CPU context.
 * Retrieves the context structure from the Per-CPU map using the CPU ID.
 */
/*
 * Return a CPU context.
 */
struct cpu_ctx *try_lookup_cpu_ctx(s32 cpu)
{
	const u32 idx = 0;
	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}

/*
 * Allocate/re-allocate a new cpumask.
 * Allocates a cpumask in BPF memory and stores it in the map as a kptr.
 */
static int calloc_cpumask(struct bpf_cpumask **p_cpumask)
{
	struct bpf_cpumask *cpumask;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	/*
	 * Atomically exchange the pointer using kptr_xchg.
	 * If it was already allocated (old pointer returned), release it.
	 */
	cpumask = bpf_kptr_xchg(p_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	return 0;
}

/*
 * Initialize a cpumask if it hasn't been initialized yet.
 * Wrapper around calloc_cpumask to prevent double allocation.
 */
static int init_cpumask(struct bpf_cpumask **cpumask)
{
	struct bpf_cpumask *mask;
	int err = 0;

	/*
	 * Do nothing if the mask is already initialized.
	 * Read into a local variable first for the BPF verifier.
	 */
	mask = *cpumask;
	if (mask)
		return 0;

	/*
	 * Create the CPU mask.
	 */
	err = calloc_cpumask(cpumask);
	if (!err)
		mask = *cpumask;
	if (!mask)
		err = -ENOMEM;

	return err;
}

/*
 * Syscall to inject topology info from userspace
 */
SEC("syscall")
int enable_sibling_cpu(struct domain_arg *input)
{
	struct cpu_ctx *cctx;
	struct bpf_cpumask *mask, **pmask;
	int err = 0;

	cctx = try_lookup_cpu_ctx(input->cpu_id);
	if (!cctx)
		return -ENOENT;

	switch (input->lvl_id) {
	case 0:
		pmask = &cctx->smt_cpumask;
		break;
	case 2:
		pmask = &cctx->l2_cpumask;
		break;
	case 3:
		pmask = &cctx->llc_cpumask;
		break;
	default:
		return -EINVAL;
	}
	err = init_cpumask(pmask);
	if (err)
		return err;

	bpf_rcu_read_lock();
	mask = *pmask;
	if (mask)
		bpf_cpumask_set_cpu(input->sibling_cpu_id, mask);
	bpf_rcu_read_unlock();

	return err;
}
