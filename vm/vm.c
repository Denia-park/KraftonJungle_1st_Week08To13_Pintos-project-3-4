/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"
#include "vm/uninit.h"
#include "vm/anon.h"
#include "vm/file.h"
#include "hash.h"
#include <string.h>

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
 /* 각 하위 시스템의 초기화 코드를 호출하여 가상 메모리 하위 시스템을 초기화합니다. */
void vm_init (void)
{
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
	page_get_type (struct page *page)
{
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
	case VM_UNINIT:
		return VM_TYPE (page->uninit.type);
	default:
		return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);
unsigned spt_entry_hash (const struct hash_elem *p_, void *aux UNUSED);
bool spt_entry_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
static void init_frame(struct frame *frame, const void *addr);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
 /* Initializer를 사용하여 보류 중인 페이지 개체를 만듭니다.
  * 페이지를 생성하려면 직접 생성하지 말고 이 함수 또는
  * `vm_alloc_page`를 통해 생성하십시오. */
bool vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
	vm_initializer *init, void *aux)
{

	ASSERT (VM_TYPE (type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *uninit = malloc(sizeof(struct page));

	/* Check wheter the upage is already occupied or not. */
	/* upage가 이미 사용 중인지 확인합니다. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		 /* TODO: 페이지를 생성하고 VM 유형에 따라 이니셜라이저를 가져온 다음,
		  * TODO: uninit_new를 호출하여 "uninit" 페이지 구조를 생성합니다.
		  * TODO: uninit_new를 호출한 후 필드를 수정해야 합니다. */
		
		bool (*type_initializer)(struct page *, enum vm_type, void *) = NULL;

		if (VM_TYPE (type) == VM_ANON) {
			type_initializer = anon_initializer;
		} else if (VM_TYPE (type) == VM_FILE) {
			type_initializer = file_backed_initializer;
		}

		uninit_new(uninit, upage, init, type, aux, type_initializer);
		uninit->writable = writable;
		uninit->aux_size = 0;

		  /* TODO: Insert the page into the spt. */
		  /* TODO: 페이지를 SPT에 삽입합니다. */
		  //기분이 좋으면 괄호 있음 ㅎㅎ. (?)
		if (!spt_insert_page(spt, uninit)) {
			goto err;
		}

		return true;
	}
err:
	free(uninit);
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
/* SPT 및 반환 페이지에서 VA를 찾습니다. 오류가 발생하면 NULL 반환. */
struct page *
	spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED)
{
	struct page page;
	/* TODO: Fill this function. */
	struct hash_elem *e;

	// TODO : 추후에 다시 한번 확인해보기.
	page.va = pg_round_down(va);
	e = hash_find (spt->spt_hash_table, &page.hash_elem);

	if (e == NULL) return NULL;

	return hash_entry (e, struct page, hash_elem);

	/* Searches hash for an element equal to element. Returns the element found, if any, or a null pointer otherwise. */
	/* 요소와 동일한 요소를 해시로 검색합니다. 발견된 요소(있는 경우)를 반환하거나 그렇지 않으면 NULL을 반환합니다. */
	// return page;
}

/* Insert PAGE into spt with validation. */
/* 유효성 검사와 함께 페이지를 spt에 삽입. */
bool spt_insert_page (struct supplemental_page_table *spt UNUSED,
	struct page *page UNUSED)
{
	/* TODO: Fill this function. */
	return hash_insert (spt->spt_hash_table, &page->hash_elem) ? false : true;
}

void spt_remove_page (struct supplemental_page_table *spt, struct page *page)
{
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void)
{
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void)
{
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space. */
 /* palloc() and get frame. 사용 가능한 페이지가 없는 경우 페이지를 삭제하고 반환합니다.
  * 항상 유효한 주소를 반환합니다. 즉, 사용자 풀 메모리가 가득 차면 이 기능은 사용 가능한
  * 메모리 공간을 얻기 위해 프레임을 제거합니다. */
static struct frame *
vm_get_frame (void)
{	
	/* TODO: Fill this function. */
	struct frame *frame = malloc(sizeof(struct frame));
	void *addr = palloc_get_page(PAL_USER);
	
	if (!addr) {
		PANIC ("todo");
	}

	init_frame(frame, addr);
 
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

static void
init_frame(struct frame *frame, const void *addr){
	frame->kva = addr;
	frame->page = NULL;
	frame->accessed = false;
	frame->dirty = false;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED)
{
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED)
{
}

/* Return true on success */
bool vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
	bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	//page_fault 에서 해당 내용을 처리하므로 아직은 내용 처리 보류
	// which first checks if it is a valid page fault.
	// By valid, we mean the fault that accesses invalid.
	// If it is a bogus fault, you load some contents into the page and
	// return control to the user program.


	//적절한 PAGE를 찾아서 do_clam_page로 넘겨야 함.
	page = spt_find_page(spt, addr);
	if(page == NULL)
		return false;

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page (struct page *page)
{
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
/* VA에 할당된 페이지를 할당합니다. */
bool vm_claim_page (void *va)
{
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page (&thread_current ()->spt, va);

	if (!page) {
		return false;
	}

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
/* 페이지를 할당하고 mmu를 설정합니다. */
static bool
vm_do_claim_page (struct page *page)
{
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	/* TODO: 페이지 테이블 항목을 삽입하여 페이지의 VA를 프레임의 PA에 매핑합니다. */
	pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable);

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
/* 새 보조 페이지 테이블 초기화 */
void supplemental_page_table_init (struct supplemental_page_table *spt)
{
	struct hash *hash_table = malloc (sizeof (struct hash));
	//! 순서 변경 필요함
	spt->spt_hash_table = hash_table;
	hash_init (spt->spt_hash_table, spt_entry_hash, spt_entry_less, NULL);
}

/* 페이지 p에 대한 해시 값을 반환합니다. */
unsigned
spt_entry_hash (const struct hash_elem *p_, void *aux UNUSED)
{
	const struct page *p = hash_entry (p_, struct page, hash_elem);
	// buf에서 시작하는 크기 바이트의 해시를 반환
	return hash_bytes (&p->va, sizeof p->va);
}

/* 요소 a와 b의 저장된 va 멤버(키)를 비교하는 함수 */
bool spt_entry_less (const struct hash_elem *a_,
	const struct hash_elem *b_, void *aux UNUSED)
{
	const struct page *a = hash_entry (a_, struct page, hash_elem);
	const struct page *b = hash_entry (b_, struct page, hash_elem);

	return a->va < b->va;
}

/* Copy supplemental page table from src to dst */
/* src에서 dst로 보조 페이지 테이블 복사 */
bool supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
	struct supplemental_page_table *src UNUSED)
{
	struct hash *src_ht = src->spt_hash_table;
	struct hash *dst_ht = dst->spt_hash_table;

	//You will need to allocate uninit page and claim them immediately.

    //hash_table 순회
	if(hash_empty(src_ht)) return true;
	
	struct hash_iterator i;
	hash_first (&i, src_ht);
	while (hash_next (&i)) {
		struct page *spt_page = hash_entry (hash_cur (&i), struct page, hash_elem);
		vm_initializer *copy_init;
		int aux_size = spt_page->aux_size;
		void *copy_aux = malloc(aux_size);
		enum vm_type curr_page_type = page_get_type(spt_page);

		if(curr_page_type == VM_UNINIT){
			copy_init = spt_page->uninit.init;
			memcpy(copy_aux, spt_page->uninit.aux, aux_size);
		}else if(curr_page_type == VM_ANON){
			copy_init = spt_page->anon.init;
			memcpy(copy_aux, spt_page->anon.aux, aux_size);
		}else if(curr_page_type == VM_FILE){
			copy_init = spt_page->file.init;
			memcpy(copy_aux, spt_page->file.aux, aux_size);
		}

		// check: aux를 malloc을 해줘야 할까 ?
		if(!vm_alloc_page_with_initializer(curr_page_type, spt_page->va, spt_page->writable, copy_init, copy_aux)){			
			free(copy_aux);
            return false;
        }

		if(spt_page->frame != NULL && spt_page->frame->kva != NULL){
			vm_claim_page(spt_page->va); // 브리기태임 굿 ! 영화 무비 공부 스터디 (4조 이름)
		}
	}

	return true;
}

void my_hash_action_func (struct hash_elem *e, void *aux){
    struct page *page = hash_entry (e, struct page, hash_elem);
	if(page->frame->kva != NULL){
		free(page->frame); // 브리
		page->frame = NULL; //브리기태 좇밥 ㅋ -> 인간시대의 끝이 도래했다.
		free(page);
	}
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED)
{
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */

	hash_clear(spt->spt_hash_table, my_hash_action_func);

	//해제 목록 정리
	//anon_destroy
		//aux -> palloc_free_page() 
	//struct frame -> my_hash_action_func 에서 처리 
	//struct page -> my_hash_action_func 에서 처리
	//hash_table -> process_exit 에서 처리
}
