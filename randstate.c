#include "randstate.h"

#include <gmp.h>
#include <stdint.h>

gmp_randstate_t state;

// Initialize the global random state for gmp using seed
// IN: seed (initial seed for the random state)
// OUT: N/A
void randstate_init(uint64_t seed) {
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, seed);
}

// Clears the memory used by the global state.
// IN: N/A
// OUT: N/A
void randstate_clear(void) {
    gmp_randclear(state);
}
