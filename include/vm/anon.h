#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
struct page;
enum vm_type;

typedef bool vm_initializer (struct page *, void *aux);

struct anon_page {
	/* uninit 페이지와 동일한 struct 구조 */
	vm_initializer *init;
	enum vm_type type;
	void *aux;
	bool (*page_initializer) (struct page *, enum vm_type, void *kva);
};

void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

#endif
