/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
	vm_anon_init();
	vm_file_init();
#ifdef EFILESYS /* For project 4 */
	pagecache_init();
#endif
	register_inspect_intr();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page)
{
	int ty = VM_TYPE(page->operations->type);
	switch (ty)
	{
	case VM_UNINIT:
		return VM_TYPE(page->uninit.type);
	default:
		return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);
unsigned spt_entry_hash(const struct hash_elem *p_, void *aux UNUSED);
bool spt_entry_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
/* Initializer를 사용하여 보류 중인 페이지 개체를 만듭니다.
 * 페이지를 생성하려면 직접 생성하지 말고 이 함수 또는
 * `vm_alloc_page`를 통해 생성하십시오. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
									vm_initializer *init, void *aux)
{

	ASSERT(VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page(spt, upage) == NULL)
	{
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
/* SPT 및 반환 페이지에서 VA를 찾습니다. 오류가 발생하면 NULL 반환. */
struct page *
spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED)
{
	struct page page;
	/* TODO: Fill this function. */
	struct hash_elem *e;

	// TODO : 추후에 다시 한번 확인해보기.
	page.va = va;
	e = hash_find(spt->spt_hash_table, &page.hash_elem);

	if (e == NULL) return NULL;

	return hash_entry(e, struct page, hash_elem);

	/* Searches hash for an element equal to element. Returns the element found, if any, or a null pointer otherwise. */
	/* 요소와 동일한 요소를 해시로 검색합니다. 발견된 요소(있는 경우)를 반환하거나 그렇지 않으면 NULL을 반환합니다. */
	// return page;
}

/* Insert PAGE into spt with validation. */
/* 유효성 검사와 함께 페이지를 spt에 삽입. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
					 struct page *page UNUSED)
{
	/* TODO: Fill this function. */
	return hash_insert(spt->spt_hash_table, &page->hash_elem) ? false : true;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
	vm_dealloc_page(page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void)
{
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
	struct frame *victim UNUSED = vm_get_victim();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame(void)
{
	struct frame *frame = NULL;
	/* TODO: Fill this function. */

	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED)
{
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED)
{
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
						 bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
	struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
	destroy(page);
	free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED)
{
	struct page *page = NULL;
	/* TODO: Fill this function */

	return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page(struct page *page)
{
	struct frame *frame = vm_get_frame();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */

	return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
/* 새 보조 페이지 테이블 초기화 */
void supplemental_page_table_init(struct supplemental_page_table *spt)
{
	struct hash *hash_table = malloc(sizeof(struct hash));
	hash_init(spt->spt_hash_table, spt_entry_hash, spt_entry_less, NULL);
	spt->spt_hash_table = hash_table;
}

/* 페이지 p에 대한 해시 값을 반환합니다. */
unsigned
spt_entry_hash(const struct hash_elem *p_, void *aux UNUSED)
{
	const struct page *p = hash_entry(p_, struct page, hash_elem);
	// buf에서 시작하는 크기 바이트의 해시를 반환
	return hash_bytes(&p->va, sizeof p->va);
}

/* 요소 a와 b의 저장된 va 멤버(키)를 비교하는 함수 */
bool spt_entry_less(const struct hash_elem *a_,
					const struct hash_elem *b_, void *aux UNUSED)
{
	const struct page *a = hash_entry(a_, struct page, hash_elem);
	const struct page *b = hash_entry(b_, struct page, hash_elem);

	return a->va < b->va;
}

/* Copy supplemental page table from src to dst */
/* src에서 dst로 보조 페이지 테이블 복사 */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
								  struct supplemental_page_table *src UNUSED)
{
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}
