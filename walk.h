#ifndef _WALK_H_
#define _WALK_H_

#include "env.h"

void *create_exec_tramp(uint32_t size, void *base);
void pagemap_t_free(pagemap_t *pmap);
void prime_set_t_free(prime_set_t *pr_set);
void ctx_t_free_prime_set(ctx_t *ctx);
void walk_descriptor_t_free(walk_descriptor_t *desc);
void pp_descriptors_t_free(pp_descriptors_t *desc);
void get_prime_set(pagemap_t pmap, ctx_t *ctx);

#endif