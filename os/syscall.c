#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "proc.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

uint64 sys_gettimeofday(uint64 val_va, int _tz) // TODO: implement sys_gettimeofday in pagetable. (VA to PA)
{
	struct proc *p = curr_proc();
    // Translate user VA → physical address
    // val_va is a user virtual address, we use useraddr() to translate it
    // to a physical address that the kernel can actually write to
    uint64 pa = useraddr(p->pagetable, val_va);
    if (pa == 0)
        return -1;
    // cast the physical address to a TimeVal pointer and write the time into it
    TimeVal *kval = (TimeVal *)pa;
    uint64 cycle   = get_cycle();
    kval->sec  = cycle / CPU_FREQ;
    kval->usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;

    return 0;
}

// TODO: add support for mmap and munmap syscall.
// hint: read through docstrings in vm.c. Watching CH4 video may also help.
// Note the return value and PTE flags (especially U,X,W,R)
static int port_to_pte(int port)
{
    // PTE_U is always set so the CPU allows user-mode access to these pages
    int pte_flags = PTE_U;  // user-accessible always
    // translate each port permission bit into its matching RISC-V PTE flag
    if (port & 0x1) pte_flags |= PTE_R;
    if (port & 0x2) pte_flags |= PTE_W;
    if (port & 0x4) pte_flags |= PTE_X;
    return pte_flags;
}

// program asks the kernel for more memory at runtime
// kernel allocates physical pages, zeroes them out, and adds them to 
// the process's virtual address space with the requested permissions
uint64 sys_mmap(uint64 start, uint64 len, int port, int flag, int fd)
{
    // reject any invalid combinations before touching memory

    // len == 0: return success immediately
    if (len == 0)
        return 0;

    // len too big (> 1 GiB)
    if (len > (1ULL << 30))
        return -1;

    // port high bits must all be zero
    if (port & ~0x7)
        return -1;

    // at least one of R/W/X must be set (all-zero is meaningless)
    if ((port & 0x7) == 0)
        return -1;

    // start must be page-aligned
    if (start % PGSIZE != 0)
        return -1;

    // Round len up to a page boundary
    uint64 len_aligned = PGROUNDUP(len);

    struct proc *p = curr_proc();

    // walk every page in the range first to make sure none are already mapped
    for (uint64 va = start; va < start + len_aligned; va += PGSIZE) {
        if (walkaddr(p->pagetable, va) != 0)
            return -1;  // page already mapped
    }

    int pte_flags = port_to_pte(port);

    for (uint64 va = start; va < start + len_aligned; va += PGSIZE) {
        // Allocate one physical page
        void *pa = kalloc();
        if (pa == 0) {
            // Out of memory — unmap what we already mapped and return error
            // (pages already mapped will be freed by uvmunmap)
            uvmunmap(p->pagetable, start, (va - start) / PGSIZE, 1);
            return -1;
        }

        // zero the page so the process cannot see leftover data from previous use
        memset(pa, 0, PGSIZE);

        // Map VA → PA in the user page table
        if (mappages(p->pagetable, va, PGSIZE, (uint64)pa, pte_flags) != 0) {
            kfree(pa);
            uvmunmap(p->pagetable, start, (va - start) / PGSIZE, 1);
            return -1;
        }
    }

    return 0;
}

// kernel removes the virtual address mappings and frees the 
// physical pages back to the free list so other processes can use them
// opposite of mmap
uint64 sys_munmap(uint64 start, uint64 len)
{
    if (len == 0)
        return 0;

    // start must be page-aligned
    if (start % PGSIZE != 0)
        return -1;

    uint64 len_aligned = PGROUNDUP(len);

    struct proc *p = curr_proc();

    // Check every page in [start, start+len) is mapped
    for (uint64 va = start; va < start + len_aligned; va += PGSIZE) {
        if (walkaddr(p->pagetable, va) == 0)
            return -1;  // unmapped page found in range
    }

    // unmap and free the physical memory for every page in the range
    uvmunmap(p->pagetable, start, len_aligned / PGSIZE, 1);

    return 0;
}
/*
* LAB1: you may need to define sys_task_info here
*/
// how long kernel has been running and how many times it has called each syscall
uint64 sys_task_info(uint64 ti_va)
{
    struct proc *p = curr_proc();

    // Translate user VA → physical address
    uint64 pa = useraddr(p->pagetable, ti_va);
    if (pa == 0)
        return -1;

    // Write directly through the physical address
    TaskInfo *kti = (TaskInfo *)pa;
    kti->status = Running;

    // copy the syscall counter array that has been tracking calls since the process started
    for (int i = 0; i < MAX_SYSCALL_NUM; i++)
        kti->syscall_times[i] = p->syscall_times[i];

    // subtract start_time from current cycle count and convert to milliseconds
    uint64 elapsed = get_cycle() - p->start_time;
    kti->time = (int)(elapsed * 1000 / CPU_FREQ);

    return 0;
}


extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	/*
	* LAB1: you may need to update syscall counter for task info here
	*/
	if (id >= 0 && id < MAX_SYSCALL_NUM) {
		curr_proc()->syscall_times[id]++;
	}

	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday(args[0], args[1]);
		break;
	/*
	* LAB1: you may need to add SYS_taskinfo case here
	*/
	case SYS_task_info:
		ret = sys_task_info(args[0]);
		break;
	case SYS_mmap:
    	ret = sys_mmap(args[0], args[1], (int)args[2], (int)args[3], (int)args[4]);
    	break;
	case SYS_munmap:
    	ret = sys_munmap(args[0], args[1]);
    	break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
