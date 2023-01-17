/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "lib/string.h"
#include "userprog/process.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);
bool lazy_load_segment(struct page *page, void *aux);

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
	// printf("addr: %p\n", addr);
	// printf("length: %ld\n", length);
	// printf("file_length: %d\n", file_length(file));
	// printf("offset: %d\n", offset);
	// printf("==============\n");

	/* TODO:
			- 파일마다 offset을 계산해서 어디서부터 읽어야 할지 알아야 함
			- while문을 돌면서 매핑하고 addr, length, offset 변경
			- 만약 읽는 바이트가 4096보다 작다면 memset으로 남는 부분 0으로 채우기
			- 성공 시 초기 addr값 반환해줘야 함
			- 실패 시 NULL 반환 ?
			- vm_alloc_page로 페이지를 만들어야함 ?
			- file 정보를 저장해야 함 ?
			- memcpy 사용 ?
			- lazy loading 해야 함 ?
			- 
	 */

	struct file *re_file = file_reopen(file); // mmap하는 동안 외부에서 해당 파일을 close 할 수 있기 때문
	void *set_addr = addr; // 마지막에 addr을 반환해줘야 하기 때문에 기존 값 저장

	while(length > 0){
		size_t read_bytes = length < PGSIZE ? length : PGSIZE; // 읽어야 하는 바이트 크기

		//이미 할당된 페이지에 접근하는지 확인
		if(spt_find_page(&thread_current()->spt, addr) != NULL){
			return NULL;
		}

		int malloc_size = sizeof(struct lazy_load_aux);
		struct lazy_load_aux *aux = malloc(malloc_size);
		*aux = (struct lazy_load_aux) {
			.file = file,
			.ofs = offset,
			.page_read_bytes = read_bytes,
			.page_zero_bytes = PGSIZE - read_bytes, // PGSIZE보다 작다면 남는 부분 0으로
		};

		if(!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_segment, aux)){
			free(aux);
			return NULL;
		}

		struct page * curr_page = spt_find_page(&thread_current()->spt, addr);
		curr_page->aux_size = malloc_size;

		length -= PGSIZE; // 읽어야 하는 남은 부분이니까 -
		offset += PGSIZE; // 읽는 시작점이니까 +
		addr += PGSIZE; // 쓰는 주소니까 +
		// printf("addr: %p\n", addr);
		// printf("length: %ld\n", length);
		// printf("file_length: %d\n", file_length(file));
		// printf("offset: %d\n", offset);
	}
	return set_addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
}
