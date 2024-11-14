// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include "../tests/snippets/test-utils.h"
#include "block_meta.h"


#define MMAP_THRESHOLD		(128 * 1024)
#define BLOCK_SIZE ALIGN(sizeof(struct block_meta))
#define ALIGN(size) (((size) + 7) & ~7)

#define SBRK_ERR ((void *) -1)

struct block_meta *block;
int preallocated_memory;

void split_block(struct block_meta *p, size_t size)
{
	if (p->size >= BLOCK_SIZE + size + 8) {
		struct block_meta *split_block = (struct block_meta *)((char *)p + BLOCK_SIZE + size);

		split_block->next = p->next;
		if (p->next)
			p->next->prev = split_block;
		p->next = split_block;
		split_block->prev = p;
		split_block->status = STATUS_FREE;
		split_block->size = p->size - BLOCK_SIZE - size;
		p->size = size;
	}
}

void coalesce_blocks(struct block_meta *p)
{
	while (p->next) {
		if (p->status == STATUS_FREE && p->next->status == STATUS_FREE) {
			p->size += p->next->size + BLOCK_SIZE;
			p->next = p->next->next;
			if (p->next)
				p->next->prev = p;
			continue;
		}
		p = p->next;
	}
}

void expand_block(struct block_meta *p, size_t size)
{
	int remaining_preallocated_memory = MMAP_THRESHOLD - ((char *)p - (char *)block) - BLOCK_SIZE - p->size;
	void *ret;

	if (remaining_preallocated_memory > 0) {
		if (remaining_preallocated_memory + p->size < size)
			ret = sbrk(size - p->size - remaining_preallocated_memory);
	} else {
		ret = sbrk(size - p->size);
	}
	DIE(ret == SBRK_ERR, "sbrk error");
	p->status = STATUS_ALLOC;
	p->size += (size - p->size);
}

void *expand_alloc_block(struct block_meta *p, size_t size)
{
	struct block_meta *q = p; // Saving last position in list for connections

	// Moving to the last block that is not mapped
	if (p->status == STATUS_MAPPED)
		while (p->status == STATUS_MAPPED)
			p = p->prev;

	// If it's allocated we try to split or expand
	if (p->status == STATUS_ALLOC) {
		int remaining_preallocated_memory = MMAP_THRESHOLD - ((char *)p - (char *)block) - BLOCK_SIZE - p->size;

		if (remaining_preallocated_memory > 8) {
			if ((size_t)remaining_preallocated_memory > size + BLOCK_SIZE) {
				// Split block
				struct block_meta *split_block = (struct block_meta *)((char *)p + BLOCK_SIZE + p->size);

				split_block->next = NULL;
				q->next = split_block;
				split_block->prev = q;
				split_block->status = STATUS_ALLOC;
				split_block->size = size;
				return (void *)((char *)split_block + BLOCK_SIZE);
			}
			// Have some preallocated memory remaining but not enough
			// Expand block
			void *ret = sbrk(size - remaining_preallocated_memory + BLOCK_SIZE);

			DIE(ret == SBRK_ERR, "sbrk error");

			// Split block
			struct block_meta *tmp = (struct block_meta *)((char *)p + BLOCK_SIZE + p->size);

			tmp->next = NULL;
			q->next = tmp;
			tmp->prev = q;
			tmp->status = STATUS_ALLOC;
			tmp->size = size;
			return (void *)((char *)tmp + BLOCK_SIZE);
		}
	}
	return NULL;
}

void *reserve_memory(struct block_meta *p, size_t size, size_t threshold)
{
	// Memory to be allocated is small => brk
	if (BLOCK_SIZE + size < threshold) {
		struct block_meta *tmp;
		void *ptr;

		if (!preallocated_memory) {
			// Preallocate memory
			ptr = sbrk(MMAP_THRESHOLD);
			DIE(ptr == SBRK_ERR, "sbrk error");
			preallocated_memory = 1;

			// Initialize block head
			block = (struct block_meta *)ptr;
			p = block;
		} else {
			// Allocate memory
			ptr = sbrk(size + BLOCK_SIZE);
			DIE(ptr == SBRK_ERR, "sbrk error");
			tmp = (struct block_meta *)ptr;
			if (p) {
				p->next = tmp;
				tmp->prev = p;
			}
			p = tmp;
		}

		p->size = size;
		p->status = STATUS_ALLOC;
		return (void *)((char *)ptr + BLOCK_SIZE);
	}
	// Memory to be allocated is big => mmap
	// Map block
	void *ptr = mmap(NULL, size + BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	DIE(ptr == MAP_FAILED, "mmap error");
	struct block_meta *tmp = (struct block_meta *)ptr;

	if (p) {
		p->next = tmp;
		tmp->prev = p;
	}

	tmp->size = size;
	tmp->status = STATUS_MAPPED;
	return (void *)((char *)ptr + BLOCK_SIZE);
}

struct block_meta *find_best_block(struct block_meta **p, size_t size)
{
	*p = block;
	struct block_meta *min_size_p = NULL;
	size_t minimum = MMAP_THRESHOLD;

	while ((*p)->next) {
		if ((*p)->status == STATUS_FREE && (*p)->size >= size) {
			if ((*p)->size < minimum) {
				min_size_p = *p;
				minimum = (*p)->size;
			}
		}
		*p = (*p)->next;
	}
	return min_size_p;
}

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;

	// Padding
	size = ALIGN(size);

	struct block_meta *p = block;

	if (p) {
		// Coalesce blocks
		coalesce_blocks(p);

		// Find best block
		struct block_meta *min_size_p = find_best_block(&p, size);

		// Found a block
		if (min_size_p) {
			// Split block or just occupy it if it's not large enough
			split_block(min_size_p, size);
			min_size_p->status = STATUS_ALLOC;
			return (void *)((char *)min_size_p + BLOCK_SIZE);
		}

		// Last block
		if (p->status == STATUS_FREE) { // Free block
			if (p->size >= size) {
				// Split block or just occupy it if it's not large enough
				split_block(p, size);
				p->status = STATUS_ALLOC;
			} else {
				// Expand last block
				expand_block(p, size);
			}
			return (void *)((char *)p + BLOCK_SIZE);
		}
		// Not free block
		void *b = expand_alloc_block(p, size);

		if (b)
			return b;
	}
	return reserve_memory(p, size, MMAP_THRESHOLD);
}

void os_free(void *ptr)
{
	if (ptr) {
		struct block_meta *p = (struct block_meta *)((char *)ptr - BLOCK_SIZE);

		if (p->status == STATUS_ALLOC) {
			p->status = STATUS_FREE;
		} else {
			// Remove the block from the list
			if (p->prev) {
				if (p->next) {
					p->prev->next = p->next;
					p->next->prev = p->prev;
				} else {
					p->prev->next = NULL;
				}
			} else {
				// The block to be removed is the first one, so we move to the next one
				if (p->next)
					block = block->next;
			}
			int ret = munmap((void *)p, p->size + BLOCK_SIZE);

			DIE(ret == -1, "munmap err");
		}
		ptr = NULL;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	size_t total_size = nmemb * size;

	if (total_size == 0)
		return NULL;

	// Padding
	total_size = ALIGN(total_size);

	struct block_meta *p = block;
	long ret = (size_t)sysconf(_SC_PAGESIZE);

	DIE(ret == -1, "sysconf err");
	unsigned long page_size = (unsigned long)ret;

	if (p) {
		// Coalesce blocks
		coalesce_blocks(p);

		// Find best block
		struct block_meta *min_size_p = find_best_block(&p, total_size);

		// Found a block
		if (min_size_p) {
			// Split block or just occupy it if it's not large enough
			if (min_size_p->status == STATUS_FREE && min_size_p->size >= total_size) {
				// Spliting block
				split_block(min_size_p, total_size);
				min_size_p->status = STATUS_ALLOC;
				void *b = (void *)((char *)min_size_p + BLOCK_SIZE);

				// Set memory to 0
				memset(b, 0, total_size);
				return b;
			}
		}

		// Last block
		if (BLOCK_SIZE + total_size < page_size) {
			if (p->status == STATUS_FREE) {
				if (p->size >= total_size) {
					// Split block
					split_block(p, total_size);
					p->status = STATUS_ALLOC;
				} else {
					// Expand last block
					expand_block(p, total_size);
				}
				void *b = (void *)((char *)p + BLOCK_SIZE);

				// Set memory to 0
				memset(b, 0, total_size);
				return b;
			}
			void *b = expand_alloc_block(p, total_size);

			if (b) {
				memset(b, 0, total_size);
				return b;
			}
		}
	}
	void *b = reserve_memory(p, total_size, page_size);

	memset(b, 0, total_size);
	return b;
}

void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return os_malloc(size);

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *p = (struct block_meta *)((char *)ptr - BLOCK_SIZE);

	if (p->status == STATUS_FREE)
		return NULL;

	// Padding
	size = ALIGN(size);

	// Memory to be reallocated is small (HEAP)
	if (BLOCK_SIZE + size < MMAP_THRESHOLD) {
		if (p->status == STATUS_ALLOC) {
			if (size <= p->size) {
				// Split block
				split_block(p, size);
				return (void *)((char *)p + BLOCK_SIZE);
			}
			if (p->next) {
				// There are blocks after this one
				int enough_space = 0;

				while (p->next && p->next->status == STATUS_FREE) {
					// Coalesce blocks
					p->size += p->next->size + BLOCK_SIZE;
					p->next = p->next->next;
					if (p->next)
						p->next->prev = p;

					if (p->size >= size) {
						enough_space = 1;
						break;
					}
				}
				// If we couldn't expand enough to fit the block, we reallocate it
				if (!enough_space) {
					void *b = os_malloc(size);

					memcpy(b, ptr, p->size);
					os_free(ptr);
					return b;
				}
			} else {
				// This is the last block
				expand_block(p, size);
			}
			return (void *)((char *)p + BLOCK_SIZE);
		}
		void *b = os_malloc(size);

		memcpy(b, ptr, size);
		os_free(ptr);
		return b;
	}
	// Memory to be reallocated is big (MAP)
	// Map block
	void *b = mmap(NULL, size + BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	struct block_meta *tmp = (struct block_meta *)b;
	struct block_meta *q = block;
	void *res = (char *)b + BLOCK_SIZE;

	DIE(b == MAP_FAILED, "mmap err");

	// Go to the last block
	while (q->next)
		q = q->next;

	// Connect new block
	q->next = tmp;
	tmp->prev = q;
	tmp->size = size;
	tmp->status = STATUS_MAPPED;

	if (p->size > size)
		memcpy(res, ptr, size);
	else
		memcpy(res, ptr, p->size);

	os_free(ptr);
	return res;
}
