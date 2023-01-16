/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;

	//1. struct frame
	free(page->frame);
	//2. aux 할당 받은거 free
	free(file_page->aux);

	return;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	/* TODO:
		- 물리 프레임 할당 (do claim 어쩌고)
		- 파일을 읽음 (file_read(file, ?, length)) , offset을 적용하기 위해 file_seek 사용
		- frame->kva 에 직접 할당 or memcpy() 사용
		- 만약 length < PGSIZE라면 memset()으로 나머지 바이트 수만큼 0으로 채우기
	 */
	
}

/* Do the munmap */
void
do_munmap (void *addr) {
}
