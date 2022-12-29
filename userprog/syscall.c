#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

typedef int pid_t;

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
static void check_address(void *addr);

static void halt (void) NO_RETURN;
static void exit (int status) NO_RETURN;
static pid_t fork (const char *thread_name);
static int exec (const char *file);
static int wait (pid_t pid);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned length);
static int write (int fd, const void *buffer, unsigned length);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	/* 포인터 유효성 검증 */
	
	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;

	case SYS_EXIT:
		exit(f->R.rdi);
		break;

	case SYS_WAIT:
		f->R.rax = wait(f->R.rdi);
		break;

	case SYS_FORK:
		break;

	case SYS_EXEC:
		check_address(f->R.rdi);
		f->R.rax = exec(f->R.rdi);
		break;

	case SYS_CREATE:
		check_address(f->R.rdi);
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;

	case SYS_REMOVE:
		check_address(f->R.rdi);
		f->R.rax = remove(f->R.rdi);
		break;

	case SYS_OPEN:
		check_address(f->R.rdi);
		f->R.rax = open(f->R.rdi);
		break;

	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;

	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;

	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;

	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;

	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;

	case SYS_CLOSE:
		check_address(f->R.rdi);
		close(f->R.rdi);
		break;

	default:
		thread_exit ();
	}
}

static void
check_address(void *addr) {
	// TODO:
	// 1. 포인터 유효성 검증
	//		<유효하지 않은 포인터>
	//		- 널 포인터
	//		- virtual memory와 매핑 안 된 영역
	//		- 커널 가상 메모리 주소 공간을 가리키는 포인터 (=PHYS_BASE 위의 영역)
	if (
		!addr
		|| pml4_get_page(thread_current()->pml4, addr)
		|| is_kernel_vaddr(addr)
	) {
		// 2. 유저 영역을 벗어난 영역일 경우 프로세스 종료((exit(-1)))
		exit(-1);
	}
}

// ! TODO: 시스템 콜의 반환값을 rax 레지스터에 저장하기

void
halt (void) {
	power_off();
}

void
exit (int status) {
	// TODO: blocked by wait
	thread_current()->exit_status = status;
	thread_exit();
}

pid_t
fork (const char *thread_name){
}

int
exec (const char *cmd_line) {
	tid_t tid = process_create_initd(cmd_line);
	struct thread *curr_thread = thread_current();

	if (tid == TID_ERROR)
	{
		return -1;
	}
	wait(tid);
}

int
wait (pid_t pid) {
	return process_wait(pid);
}

bool
create (const char *file, unsigned initial_size) {
	return filesys_create(file, initial_size);
}

bool
remove (const char *file) {
	return filesys_remove(file);
}

int
open (const char *file) {

	struct thread *curr_t = thread_current();
	struct file *f = filesys_open(file);

	if (f) { // FIXME: next_fd 갱신 로직 최적화
		curr_t->fdt[curr_t->next_fd] = f;
		return curr_t->next_fd++;
	}
	else {
		return -1;
	}
}

int
filesize (int fd) {
	struct thread *curr_t = thread_current();
	struct file *file_p = curr_t->fdt[fd];
	if (file_p == NULL) {
		return -1;
	}
	return file_length(file_p);
}

int
read (int fd, void *buffer, unsigned size) {
	
	if (fd == STDIN_FILENO)
	{	
		int i;
		uint8_t key;
		for (i=0; i<size; i++)
		{
			key = input_getc();
			*(char *)buffer++ = key;
			if (key == '\0')
			{
				i++;
				break;
			}
		}
		return i;
	}
	else if (fd == STDOUT_FILENO)
	{
		return -1;
	}
	else
	{
		/* 파일 디스크립터에 해당하는 파일을 가져와야한다. */
		struct thread *curr_thread = thread_current();
		struct file **fdt = curr_thread->fdt;
		// TODO: lock acquire failed
		struct file *curr_file = fdt[fd];
		lock_acquire(&filesys_lock);
		off_t read_size = file_read(curr_file, buffer, size);
		lock_release(&filesys_lock);

		// if (file == NULL)
		// 	return -1;
		// if (curr_file->inode->open_cnt == 0)
		// 	lock_acquire(curr_file->write_lock);

		// lock_acquire(curr_file->read_lock);
		// curr_file->inode->open_cnt++;
		// lock_release(curr_file->read_lock);

		
		// lock_acquire(curr_file->read_lock);
		// curr_file->inode->open_cnt--;
		// lock_release(curr_file->read_lock);

		// if (curr_file->inode->open_cnt == 0)
		// 	lock_release(curr_file->write_lock);

		return read_size;

	}
	
}

int
write (int fd, const void *buffer, unsigned size) {

	struct thread *curr_thread = thread_current();
	struct file **fdt = curr_thread->fdt;
	struct file *fileobj = fdt[fd];
	int read_count;

	if (fd == 1) {
		putbuf(buffer, size);
		read_count = size;
	}	
	
	else if (fd == STDIN_FILENO) {
		return -1;
	}

	else {

		lock_acquire(&filesys_lock);
		read_count = file_write(fileobj, buffer, size);
		lock_release(&filesys_lock);
	}
	return read_count;
}

void
seek (int fd, unsigned position) {
	struct thread *curr_thread = thread_current();
	struct file **fdt = curr_thread->fdt;
	struct file *curr_file = fdt[fd];
	
	file_seek (curr_file, position);
}

unsigned
tell (int fd) {
	struct thread *curr_thread = thread_current();
	struct file **fdt = curr_thread->fdt;
	struct file *curr_file = fdt[fd];
	return file_tell(curr_file);
}

void
close (int fd) {// FIXME: next_fd 갱신 로직 최적화
	struct thread *curr_t = thread_current();
	struct file *file_p = curr_t->fdt[fd];
	file_close(file_p);
	curr_t->fdt[fd] = NULL;
}
