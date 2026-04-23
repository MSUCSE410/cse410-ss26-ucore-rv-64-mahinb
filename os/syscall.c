#include "syscall.h"
#include "console.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "proc.h"
#include "timer.h"
#include "trap.h"

// Stat structure passed to user space
typedef struct {
	uint64 dev;      // device id
	uint64 ino;      // inode number
	uint32 mode;     // not used, set 0
	uint32 nlink;    // number of hard links
	uint64 pad[7];   // padding
} Stat;

uint64 console_write(uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	tracef("write size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return len;
}

uint64 console_read(uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	tracef("read size = %d", len);
	for (int i = 0; i < len; ++i) {
		int c = consgetc();
		str[i] = c;
	}
	copyout(p->pagetable, va, str, len);
	return len;
}

uint64 sys_write(int fd, uint64 va, uint64 len)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d\n", fd);
		return -1;
	}
	switch (f->type) {
	case FD_STDIO:
		return console_write(va, len);
	case FD_INODE:
		return inodewrite(f, va, len);
	default:
		panic("unknown file type %d\n", f->type);
	}
}

uint64 sys_read(int fd, uint64 va, uint64 len)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d\n", fd);
		return -1;
	}
	switch (f->type) {
	case FD_STDIO:
		return console_read(va, len);
	case FD_INODE:
		return inoderead(f, va, len);
	default:
		panic("unknown file type %d\n", f->type);
	}
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

uint64 sys_gettimeofday(uint64 val, int _tz)
{
	struct proc *p = curr_proc();
	uint64 cycle = get_cycle();
	TimeVal t;
	t.sec = cycle / CPU_FREQ;
	t.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	copyout(p->pagetable, val, (char *)&t, sizeof(TimeVal));
	return 0;
}

uint64 sys_getpid()
{
	return curr_proc()->pid;
}

uint64 sys_getppid()
{
	struct proc *p = curr_proc();
	return p->parent == NULL ? IDLE_PID : p->parent->pid;
}

uint64 sys_clone()
{
	debugf("fork!");
	return fork();
}

static inline uint64 fetchaddr(pagetable_t pagetable, uint64 va)
{
	uint64 *addr = (uint64 *)useraddr(pagetable, va);
	return *addr;
}

uint64 sys_exec(uint64 path, uint64 uargv)
{
	struct proc *p = curr_proc();
	char name[MAX_STR_LEN];
	copyinstr(p->pagetable, name, path, MAX_STR_LEN);
	uint64 arg;
	static char strpool[MAX_ARG_NUM][MAX_STR_LEN];
	char *argv[MAX_ARG_NUM];
	int i;
	for (i = 0; uargv && (arg = fetchaddr(p->pagetable, uargv));
	     uargv += sizeof(char *), i++) {
		copyinstr(p->pagetable, (char *)strpool[i], arg, MAX_STR_LEN);
		argv[i] = (char *)strpool[i];
	}
	argv[i] = NULL;
	return exec(name, (char **)argv);
}

uint64 sys_wait(int pid, uint64 va)
{
	struct proc *p = curr_proc();
	int *code = (int *)useraddr(p->pagetable, va);
	return wait(pid, code);
}

uint64 sys_spawn(uint64 va)
{
    struct proc *p = curr_proc();
    char name[200];
    copyinstr(p->pagetable, name, va, 200);
    debugf("sys_spawn %s\n", name);

    struct inode *ip = namei(name);
    if (ip == 0)
        return -1;

    struct proc *np = allocproc();
    if (np == 0) {
        iput(ip);
        return -1;
    }

    init_stdio(np);
    bin_loader(ip, np);
    iput(ip);

    np->parent = p;
    np->state = RUNNABLE;

    char *argv[2];
    argv[0] = name;
    argv[1] = NULL;
    np->trapframe->a0 = push_argv(np, argv);

    return np->pid;
}

uint64 sys_set_priority(long long prio)
{
    if (prio < 2) // priority must be >= 2
        return -1;

    struct proc *p = curr_proc(); // get the calling process
    p->priority = prio; // update its priority
    return prio;
}

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

uint64 sys_openat(uint64 va, uint64 omode, uint64 _flags)
{
	struct proc *p = curr_proc();
	char path[200];
	copyinstr(p->pagetable, path, va, 200);
	return fileopen(path, omode);
}

uint64 sys_close(int fd)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d", fd);
		return -1;
	}
	fileclose(f);
	p->files[fd] = 0;
	return 0;
}

// Implements the fstat syscall (ID 80).
// Given an open file descriptor, fills a user-space Stat struct with
// metadata about the underlying inode: device number, inode number,
// file type (translated to the user-space mode bitmask), and the
// current hard link count. Returns -1 on invalid fd or copy failure,
// 0 on success.
#define STAT_FILE 0x100000 // user-space mode constant for regular files
#define STAT_DIR  0x040000 // user-space mode constant for directories

int sys_fstat(int fd, uint64 stat)
{
    struct proc *p = curr_proc();  // get the calling process

    // validate that fd is within the legal range of the process's fd table
    if (fd < 0 || fd >= FD_BUFFER_SIZE)
        return -1;

    struct file *f = p->files[fd];  // look up the open file struct for this fd

    // fd must be open and must point to an on-disk inode (not stdio)
    if (f == NULL || f->type != FD_INODE)
        return -1;

    struct inode *ip = f->ip;  // get the inode that this file refers to
    ivalid(ip);                // make sure type, nlink, size are loaded from disk

    // build the stat struct in kernel memory before copying to user space
    Stat st;
    memset(&st, 0, sizeof(st));  // zero out the entire struct including pad[]

    st.dev = ip->dev;    // device number this inode lives on
    st.ino = ip->inum;   // inode number on disk

    // translate the on-disk type (T_FILE=2, T_DIR=1) to the user-space
    // mode bitmask that the test program expects (FILE=0x100000, DIR=0x040000)
    st.mode = (ip->type == T_DIR) ? STAT_DIR : STAT_FILE;

    st.nlink = ip->nlink;  // current number of hard links pointing at this inode

    // copy the filled-in struct from kernel memory into the user's buffer
    if (copyout(p->pagetable, stat, (char *)&st, sizeof(st)) < 0)
        return -1;  // user provided an invalid address
    return 0;
}

// Implements the linkat syscall (ID 37).
// Creates a new hard link: adds a second directory entry (newpath) in the
// root directory that points to the same inode as oldpath. Increments the
// inode's nlink so the file persists until all links are removed.
// Only works on regular files (not directories). If the new name already
// exists or matches the old name, returns -1. On dirlink failure, rolls
// back the nlink increment to avoid a phantom link count.
// olddirfd, newdirfd, and flags are ignored per the lab spec.
int sys_linkat(int olddirfd, uint64 oldpath, int newdirfd, uint64 newpath, uint64 flags)
{
	struct proc *p = curr_proc();  // get the calling process
	char old[MAXPATH], new[MAXPATH];

	// copy both path strings from user space into kernel buffers
	copyinstr(p->pagetable, old, oldpath, MAXPATH);
	copyinstr(p->pagetable, new, newpath, MAXPATH);

	// can't create a link with the same name as the original —
	// that entry already exists in the directory
	if (strncmp(old, new, MAXPATH) == 0)
		return -1;

	// look up the inode for the original file
	struct inode *ip = namei(old);
	if (ip == 0)
		return -1;  // original file doesn't exist

	ivalid(ip);  // load type and nlink from disk into memory

	// hard links to directories are not allowed — only regular files
	if (ip->type != T_FILE) {
		iput(ip);  // release the ref we got from namei
		return -1;
	}

	// increment the link count first and write to disk, so the inode
	// reflects the new link even if we crash between here and dirlink
	ip->nlink++;
	iupdate(ip);  // persist the incremented nlink to disk

	// open the root directory and add a new entry mapping newpath -> same inum
	struct inode *dp = root_dir();
	if (dirlink(dp, new, ip->inum) < 0) {
		// dirlink failed (e.g. name already exists) — roll back
		ip->nlink--;   // undo the nlink bump
		iupdate(ip);   // persist the rollback to disk
		iput(ip);      // release file inode ref
		iput(dp);      // release root dir ref
		return -1;
	}

	iput(dp);  // release root directory reference
	iput(ip);  // release file inode reference (nlink >= 2 now, so it won't be freed)
	return 0;
}

// Implements the unlinkat syscall (ID 35).
// Removes a hard link by deleting the directory entry for the given path
// from the root directory and decrementing the inode's nlink count.
// When nlink reaches 0, the final iput call will detect that no links
// remain and no other references exist, then truncate all data blocks
// and mark the inode as free on disk — effectively deleting the file.
// dirfd and flags are ignored per the lab spec.
// Returns -1 if the file doesn't exist, 0 on success.
int sys_unlinkat(int dirfd, uint64 name, uint64 flags)
{
	struct proc *p = curr_proc();  // get the calling process
	char path[MAXPATH];

	// copy the filename from user space into a kernel buffer
	copyinstr(p->pagetable, path, name, MAXPATH);

	// look up the inode for the file being unlinked
	struct inode *ip = namei(path);
	if (ip == 0)
		return -1;  // file doesn't exist

	ivalid(ip);  // load type, nlink, size from disk so we can modify nlink

	// open the root directory to remove the directory entry
	struct inode *dp = root_dir();

	// erase the directory entry (zero out its dirent slot)
	if (dirunlink(dp, path) < 0) {
		iput(dp);  // release root dir ref
		iput(ip);  // release file inode ref
		return -1; // shouldn't normally fail since namei already found it
	}

	// decrement the link count now that one fewer name points to this inode
	ip->nlink--;
	iupdate(ip);  // write the decremented nlink to disk

	iput(dp);  // release root directory reference

	// release file inode reference — if nlink just hit 0 and this is the
	// last ref (ref == 1 before decrement), iput will call itrunc to free
	// all data blocks and mark the on-disk inode as free (type = 0)
	iput(ip);
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

	if (id >= 0 && id < MAX_SYSCALL_NUM) {
		curr_proc()->syscall_times[id]++;
	}		  		   
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_read:
		ret = sys_read(args[0], args[1], args[2]);
		break;
	case SYS_openat:
		ret = sys_openat(args[0], args[1], args[2]);
		break;
	case SYS_close:
		ret = sys_close(args[0]);
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
	case SYS_getpid:
		ret = sys_getpid();
		break;
	case SYS_getppid:
		ret = sys_getppid();
		break;
	case SYS_clone: // SYS_fork
		ret = sys_clone();
		break;
	case SYS_execve:
		ret = sys_exec(args[0], args[1]);
		break;
	case SYS_wait4:
		ret = sys_wait(args[0], args[1]);
		break;
	case SYS_fstat:
	    ret = sys_fstat(args[0],args[1]);
		break;
	case SYS_linkat:
	    ret = sys_linkat(args[0],args[1],args[2],args[3],args[4]);
		break;
	case SYS_unlinkat:
	    ret = sys_unlinkat(args[0],args[1],args[2]);
		break;
	case SYS_spawn:
		ret = sys_spawn(args[0]);
		break;
		
	case SYS_task_info:
		ret = sys_task_info(args[0]);
		break;
	case SYS_mmap:
    	ret = sys_mmap(args[0], args[1], (int)args[2], (int)args[3], (int)args[4]);
    	break;
	case SYS_munmap:
    	ret = sys_munmap(args[0], args[1]);
    	break;		
	case SYS_setpriority:
		ret = sys_set_priority(args[0]);
		break;		
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
