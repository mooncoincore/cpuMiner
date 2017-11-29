#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "balloon/balloon.h"
#include "balloon/constants.h"
#include "balloon/hash_state.h"

static void balloonpow_init (struct balloon_options *opts){
  opts->s_cost = 128;
  opts->t_cost = 1;
  opts->n_threads = 1;
}

void balloon_hash(unsigned char *input, unsigned char *output)
{
  int i;
  struct balloon_options opts;
  balloonpow_init(&opts);
  struct hash_state s;
  hash_state_init(&s,&opts,input);
  hash_state_fill(&s,input,input,80);
  for(i=0; i<3; i++)
     hash_state_mix(&s);
  hash_state_extract(&s,output);
  hash_state_free (&s);
}

int scanhash_balloon(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) hash[8];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	for (int k=0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	do {
		be32enc(&endiandata[19], nonce);
		balloon_hash(endiandata, hash);

		if (hash[7] <= Htarg) { // && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
