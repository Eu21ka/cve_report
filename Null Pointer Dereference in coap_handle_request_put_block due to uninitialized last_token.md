## Null Pointer Dereference in `coap_handle_request_put_block` due to uninitialized `last_token`

**Affected Component:** `src/coap_block.c` (Function: `coap_handle_request_put_block`)

**Affected Version:** libcoap 4.3.5 (and potentially earlier versions)

**Vulnerability Type:** Null Pointer Dereference (CWE-476)

**Impact:** Denial of Service (Server Crash)

#### 1. Summary
A Null Pointer Dereference vulnerability exists in `src/coap_block.c` when handling CoAP Block-wise transfers (BLOCK1). When processing a standard BLOCK1 request (non-Q-Block) where the "More" bit is set (`m=1`), the `last_token` member of the `coap_lg_srcv_t` structure is not correctly updated/initialized.

If a specific sequence of packets causes the server to determine that all blocks have been received (despite `m=1`), the code attempts to dereference `lg_srcv->last_token` to update the response token, resulting in a Segmentation Fault because `last_token` is NULL.

#### 2. Root Cause Analysis
The vulnerability stems from a logical gap in how `last_token` is maintained during the lifecycle of a block-wise transfer:

1.  When a new `lg_srcv` is allocated, it is zero-initialized, so `lg_srcv->last_token` is `NULL`.
2.  The code has specific logic to update `last_token` for **Q-Block1** options.
3.  The code also updates `last_token` for standard **BLOCK1** options when it is the **last block** (`m=0`).
4.  **The Gap:** There is **no code** to update `last_token` for a standard **BLOCK1** option when the **"More" bit is set (`m=1`)**.
5.  Under normal circumstances, an `m=1` packet simply triggers a 2.31 (Continue) response and returns. However, if the internal logic (`check_all_blocks_in`) determines that the full payload has been reassembled (e.g., due to packet reordering or specific size calculations), the code enters the completion handler block.
6.  Inside this block, at line 3108, the code unconditionally accesses `lg_srcv->last_token`:
    ```c
    // src/coap_block.c:3108
    coap_update_token(response, lg_srcv->last_token->length, lg_srcv->last_token->s);
    ```
    Since the token was never updated for this `m=1` packet, `last_token` is `NULL`, causing a crash.

#### 3. Crash Evidence (GDB)
Debugging with GDB confirms that `lg_srcv->last_token` is `NULL` at the time of the crash.

```text
Thread 1 "coap-server" received signal SIGSEGV, Segmentation fault.
0x00005555556b50ce in coap_handle_request_put_block (context=0x614000000040, session=0x617000000080, pdu=0x60c0000049c0, response=0x60c000004a80, resource=0x610000000040, uri_path=0x603000001ba0, observe=0x0, added_block=0x7fffffffa8d0, pfree_lg_srcv=0x7fffffffa8e0) at src/coap_block.c:3108
3108            coap_update_token(response, lg_srcv->last_token->length, lg_srcv->last_token->s);
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
──────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────
 RAX  0
 RBX  0x7fffffff9b60 ◂— 0x7e /* '~' */
 RCX  0x7fffffff9320 ◂— 0x45e0360e
 RDX  0
 RDI  0x7ffff729c060 ◂— 1
 RSI  0x7ffff729c0e0 ◂— 0
 R8   0x80
 R9   0x7ffff5002530 —▸ 0x555555778101 (coap_delete_pdu+433) ◂— add rsp, 0x30
 R10  0x7fffffff8aa8 —▸ 0x555555778101 (coap_delete_pdu+433) ◂— add rsp, 0x30
 R11  0x70
 R12  0x55555622fcc0 (__afl_area_initial) —▸ 0x10000000000 ◂— 0
 R13  0x829
 R14  0x617000000080 —▸ 0x200000003 ◂— 0
 R15  0x614000000040 ◂— 0
 RBP  0x7fffffffa7f0 —▸ 0x7fffffffb6f0 —▸ 0x7fffffffc4d0 —▸ 0x7fffffffd0b0 —▸ 0x7fffffffd430 ◂— ...
 RSP  0x7fffffff9a20 ◂— 0x41b58ab3
 RIP  0x5555556b50ce (coap_handle_request_put_block+23198) ◂— mov rax, qword ptr [rax]
───────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────
 ► 0x5555556b50ce <coap_handle_request_put_block+23198>    mov    rax, qword ptr [rax]               <Cannot dereference [0]>
   0x5555556b50d1 <coap_handle_request_put_block+23201>    mov    qword ptr [rbx + 0x1a0], rax
   0x5555556b50d8 <coap_handle_request_put_block+23208>    mov    rax, qword ptr [rbx + 0xbe8]       RAX, [0x7fffffffa748]
   0x5555556b50df <coap_handle_request_put_block+23215>    add    rax, 0x78
   0x5555556b50e3 <coap_handle_request_put_block+23219>    mov    qword ptr [rbx + 0x1a8], rax
   0x5555556b50ea <coap_handle_request_put_block+23226>    shr    rax, 3
   0x5555556b50ee <coap_handle_request_put_block+23230>    cmp    byte ptr [rax + 0x7fff8000], 0
   0x5555556b50f5 <coap_handle_request_put_block+23237>    je     coap_handle_request_put_block+23255 <coap_handle_request_put_block+23255>
 
   0x5555556b50fb <coap_handle_request_put_block+23243>    mov    rdi, qword ptr [rbx + 0x1a8]
   0x5555556b5102 <coap_handle_request_put_block+23250>    call   __asan_report_load8         <__asan_report_load8>
 
   0x5555556b5107 <coap_handle_request_put_block+23255>    mov    rax, qword ptr [rbx + 0x1a8]
────────────────────────────────────────────────────────────────[ SOURCE (CODE) ]─────────────────────────────────────────────────────────────────
In file: /home/eur1ka/fuzz/libcoap-4.3.5/src/coap_block.c:3108
   3103                                                      NULL);
   3104         if (tmp_pdu) {
   3105           tmp_pdu->code = COAP_RESPONSE_CODE(231);
   3106           coap_send_internal(session, tmp_pdu);
   3107         }
 ► 3108         coap_update_token(response, lg_srcv->last_token->length, lg_srcv->last_token->s);
   3109         coap_update_token(pdu, lg_srcv->last_token->length, lg_srcv->last_token->s);
   3110         /* Pass the assembled pdu and body to the application */
   3111         goto give_app_data;
   3112       }
   3113     } else {
────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffff9a20 ◂— 0x41b58ab3
01:0008│-dc8 0x7fffffff9a28 —▸ 0x555555862889 ◂— '8 32 8 11 length:2796 64 8 9 data:2797 96 8 11 offset:2798 128 8 10 total:2799 160 12 10 block:2800 192 40 13 opt_iter:2801 272 4 8 buf:2882 288 4 11 buf471:3050'
02:0010│-dc0 0x7fffffff9a30 —▸ 0x5555556af630 (coap_handle_request_put_block) ◂— push rbp
03:0018│-db8 0x7fffffff9a38 —▸ 0x55555575b801 (coap_check_option+337) ◂— mov rdx, qword ptr [rbx + 0x18]
04:0020│-db0 0x7fffffff9a40 ◂— 0
05:0028│-da8 0x7fffffff9a48 —▸ 0x55555586e9c8 ◂— '1 32 12 5 f:201'
06:0030│-da0 0x7fffffff9a50 —▸ 0x55555575b6b0 (coap_check_option) ◂— push rbp
07:0038│-d98 0x7fffffff9a58 ◂— 0
──────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────
 ► 0   0x5555556b50ce coap_handle_request_put_block+23198
   1   0x555555749e82 handle_request+20370
   2   0x55555573bf25 coap_dispatch+28117
   3   0x555555733841 coap_read_session+5425
   4   0x55555573e522 coap_io_do_epoll_lkd+4802
   5   0x55555571758a coap_io_process_with_fds_lkd+2954
   6   0x5555557169f8 coap_io_process_lkd+88
   7   0x555555716932 coap_io_process+178
──────────────────────────────────────────────────────────────[ THREADS (2 TOTAL) ]───────────────────────────────────────────────────────────────
  ► 1   "coap-server" stopped: 0x5555556b50ce <coap_handle_request_put_block+23198> 
    2   "coap-server" stopped: 0x5555555ae01a <__sanitizer::SizeClassAllocator64LocalCache<__sanitizer::SizeClassAllocator64<__asan::AP64<__sanitizer::LocalAddressSpaceView> > >::Refill(__sanitizer::SizeClassAllocator64LocalCache<__sanitizer::SizeClassAllocator64<__asan::AP64<__sanitizer::LocalAddressSpaceView> > >::PerClass*, __sanitizer::SizeClassAllocator64<__asan::AP64<__sanitizer::LocalAddressSpaceView> >*, unsigned long)+90> 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> p lg_srcv
$1 = (coap_lg_srcv_t *) 0x60e0000002e0
pwndbg> p lg_srcv->last_
last_mid    last_token  last_type   last_used   
pwndbg> p lg_srcv->last_token 
$2 = (coap_bin_const_t *) 0x0
```

#### 4. Reproduction Steps
1. Compile `libcoap` with ASAN enabled for better visibility:
   ```bash
   ./configure --disable-doxygen --disable-manpages CFLAGS="-g -O0 -fsanitize=address" LDFLAGS="-fsanitize=address"
   make
   ```
2. Gdb the server:
   ```bash
   LD_PRELOAD=~/tools/desockmulti/desockmulti.so gdb --args examples/coap-server 
   ```
3. run:

   ```
   pwndbg> run < <crash_input>
   ```

