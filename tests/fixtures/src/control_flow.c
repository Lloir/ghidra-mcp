#include <stdint.h>

static volatile uint32_t runtime_seed = 0x9e3779b9u;

typedef uint32_t (*state_handler)(uint32_t *, uint32_t);

__attribute__((noinline)) static uint32_t mix_xor(uint32_t *result, uint32_t salt) {
    *result ^= salt;
    return (*result >> 3) & 3u;
}

__attribute__((noinline)) static uint32_t mix_rotate(uint32_t *result, uint32_t salt) {
    *result = (*result << 7) | (*result >> 25);
    return (*result ^ salt) & 3u;
}

__attribute__((noinline)) static uint32_t mix_add(uint32_t *result, uint32_t salt) {
    *result += salt | 1u;
    return (*result >> 11) & 3u;
}

__attribute__((noinline)) static uint32_t mix_invert(uint32_t *result, uint32_t salt) {
    *result = ~*result ^ (salt << 1);
    return (*result >> 19) & 3u;
}

static state_handler const dispatch[] = {mix_xor, mix_rotate, mix_add, mix_invert};

__attribute__((visibility("default")))
uint32_t fixture_control_flow(uint32_t value) {
    uint32_t result = value;
    uint32_t state = (value ^ runtime_seed) & 3u;
    for (uint32_t round = 0; round < 12u; ++round) {
        /* Runtime-mutable state together with the function-pointer table keep the optimizer from folding the dispatch path. */
        state = dispatch[state](&result, runtime_seed + round);
    }
    return result ^ state ^ 0x10203040u;
}
