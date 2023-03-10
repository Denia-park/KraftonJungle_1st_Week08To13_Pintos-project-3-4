#ifndef VM_VM_H
#define VM_VM_H
#include <stdbool.h>
#include "threads/palloc.h"
#include "kernel/hash.h"

enum vm_type {
	/* page not initialized */
	VM_UNINIT = 0,
	/* page not related to the file, aka anonymous page */
	VM_ANON = 1,
	/* page that realated to the file */
	VM_FILE = 2,
	/* page that hold the page cache, for project 4 */
	VM_PAGE_CACHE = 3,

	/* Bit flags to store state */

	/* Auxillary bit flag marker for store information. You can add more
	 * markers, until the value is fit in the int. */
	VM_MARKER_0 = (1 << 3),
	VM_MARKER_1 = (1 << 4),

	/* DO NOT EXCEED THIS VALUE. */
	VM_MARKER_END = (1 << 31),
};

enum locate {
	FRAME = 0, // 프레임
	DISK = 1, // 디스크
	SWAP = 2 // 스왑 공간
};

#include "vm/uninit.h"
#include "vm/anon.h"
#include "vm/file.h"
#ifdef EFILESYS
#include "filesys/page_cache.h"
#endif

struct page_operations;
struct thread;

#define VM_TYPE(type) ((type) & 7)

/* The representation of "page".
 * This is kind of "parent class", which has four "child class"es, which are
 * uninit_page, file_page, anon_page, and page cache (project4).
 * DO NOT REMOVE/MODIFY PREDEFINED MEMBER OF THIS STRUCTURE. */
/* "page"를 나타냅니다.
 * 이것은 "부모 클래스"의 일종으로 uninit_page, file_page, anon_page,
 * and page cache (project4)네 개의 "자녀 클래스"를 가지고 있다.
 * 이 구조체의 미리 정의된 멤버를 제거하거나 수정하지 마십시오. */
struct page {
	const struct page_operations *operations;
	void *va;              /* Address in terms of user space */ // 사용자 공간 측면의 주소
	struct frame *frame;   /* Back reference for frame */ // 프레임에 대한 역참조

	/* Your implementation */
	struct hash_elem hash_elem; // 해시 요소
	bool active; // 활성화 체크
	enum locate locate; // page 위치
	bool writable;
	int aux_size;

	/* Per-type data are binded into the union.
	 * Each function automatically detects the current union */
	/* 유형별 데이터가 유니온에 바인딩됩니다.
	 * 각 함수는 현재 유니온을 자동으로 감지합니다. */
	union {
		struct uninit_page uninit;
		struct anon_page anon;
		struct file_page file;
#ifdef EFILESYS
		struct page_cache page_cache;
#endif
	};
};

/* The representation of "frame" */
struct frame {
	void *kva;
	struct page *page;
	bool accessed;
	bool dirty;
};

/* The function table for page operations.
 * This is one way of implementing "interface" in C.
 * Put the table of "method" into the struct's member, and
 * call it whenever you needed. */
struct page_operations {
	bool (*swap_in) (struct page *, void *);
	bool (*swap_out) (struct page *);
	void (*destroy) (struct page *);
	enum vm_type type;
};

#define swap_in(page, v) (page)->operations->swap_in ((page), v)
#define swap_out(page) (page)->operations->swap_out (page)
#define destroy(page) \
	if ((page)->operations->destroy) (page)->operations->destroy (page)

/* Representation of current process's memory space.
 * We don't want to force you to obey any specific design for this struct.
 * All designs up to you for this. */
/* 현재 프로세스의 메모리 공간을 나타냅니다.
 * 우리는 당신에게 이 구조에 대한 어떤 특정한 설계도를 따르도록 강요하고 싶지 않습니다.
 * 이것에 대한 모든 설계는 당신에게 달려있습니다. */
struct supplemental_page_table {
	struct hash* spt_hash_table;
};

#include "threads/thread.h"
void supplemental_page_table_init (struct supplemental_page_table *spt);
bool supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src);
void supplemental_page_table_kill (struct supplemental_page_table *spt);
struct page *spt_find_page (struct supplemental_page_table *spt,
		void *va);
bool spt_insert_page (struct supplemental_page_table *spt, struct page *page);
void spt_remove_page (struct supplemental_page_table *spt, struct page *page);

void vm_init (void);
bool vm_try_handle_fault (struct intr_frame *f, void *addr, bool user,
		bool write, bool not_present);

#define vm_alloc_page(type, upage, writable) \
	vm_alloc_page_with_initializer ((type), (upage), (writable), NULL, NULL)
bool vm_alloc_page_with_initializer (enum vm_type type, void *upage,
		bool writable, vm_initializer *init, void *aux);
void vm_dealloc_page (struct page *page);
bool vm_claim_page (void *va);
enum vm_type page_get_type (struct page *page);

struct lazy_load_aux {
	struct file *file;
	off_t ofs;
	size_t page_read_bytes;
	size_t page_zero_bytes;
};

#endif  /* VM_VM_H */
