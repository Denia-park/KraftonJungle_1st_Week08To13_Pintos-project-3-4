#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H
/* for byte alignment */
#define ALIGNMENT 8
#define FD_LIMIT_LEN 128
#define ADDR_SIZE sizeof(void *)
#define CHARP_SIZE sizeof(char *)

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);
int get_next_fd (struct file **);
// static int parse_file_name (char **argv, const char *file_name);
// static void pass_arguments (int argc, char **argv, struct intr_frame *if_);
// static struct thread *get_child_with_id (tid_t child_tid);

#endif /* userprog/process.h */
