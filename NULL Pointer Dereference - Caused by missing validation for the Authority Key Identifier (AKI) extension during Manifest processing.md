### Developer response

![截屏2026-01-12 09.16.07](https://picture-1312228068.cos.ap-shanghai.myqcloud.com/image2026-01-12%2009.16.07.png)

**Official fix:**
```c
Index: parser.c
===================================================================
RCS file: /cvs/src/usr.sbin/rpki-client/parser.c,v
diff -u -p -r1.173 parser.c
--- parser.c	13 Nov 2025 15:18:53 -0000	1.173
+++ parser.c	9 Jan 2026 15:51:02 -0000
@@ -589,6 +589,13 @@ proc_parser_cert(char *file, const unsig
	if (cert == NULL)
		goto out;

+	if (cert->purpose != CERT_PURPOSE_CA &&
+	    cert->purpose != CERT_PURPOSE_BGPSEC_ROUTER) {
+		warnx("%s: %s not allowed in a manifest", file,
+		    purpose2str(cert->purpose));
+		goto out;
+	}
+
	a = find_issuer(file, entp->certid, cert->aki, entp->mftaki);
	if (a == NULL)
		goto out;
@@ -892,6 +899,7 @@ parse_entity(struct entityq *q, struct i
			/*
			 * If entp->datasz == SHA256_DIGEST_LENGTH, we have a
			 * cert added from a manifest, so it is not a root cert.
+			 * proc_parser_cert() will also make sure of this.
			 */
			if (entp->data != NULL &&
			    entp->datasz != SHA256_DIGEST_LENGTH) {
```

### Vulnerability report

**Type:** NULL Pointer Dereference / Segmentation Fault

**Location:** `src/parser.c` function `find_issuer`

**Description:**
When `rpki-client` parses an X.509 certificate that lacks the Authority Key Identifier (AKI) extension, the internal `cert->aki` member is set to `NULL`.

If this malformed certificate is processed within a Manifest validation context (where `mftaki` is present), the `find_issuer` function passes the `NULL` `aki` pointer directly to `strcmp`, causing a crash:

```c
//src/parser.c:116
static struct auth *
find_issuer(const char *fn, int id, const char *aki, const char *mftaki)
{
	struct auth *a;
	//...
	if (mftaki != NULL) {
		if (strcmp(aki, mftaki) != 0) {  // aki is NULL here
			warnx("%s: AKI %s doesn't match Manifest AKI %s", fn,
			    aki, mftaki);
			return NULL;
		}
	}
	//...
	return a;
}
```

**GDB:**

```c
─────────────────────────────────────────────────────[ SOURCE (CODE) ]─────────────────────────────────────────────────────
In file: /home/eur1ka/fuzz/rpki-client-9.6/src/parser.c:130
   125                             aki);
   126                 return NULL;
   127         }
   128 
   129         if (mftaki != NULL) {
 ► 130                 if (strcmp(aki, mftaki) != 0) {
   131                         warnx("%s: AKI %s doesn't match Manifest AKI %s", fn,
   132                             aki, mftaki);
   133                         return NULL;
   134                 }
   135         }
─────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffff26fca10 —▸ 0x504000000250 ◂— '28E69049B3B43625D56CFF67F91AE1FBDB70431D'
01:0008│-028 0x7ffff26fca18 ◂— 0
02:0010│-020 0x7ffff26fca20 —▸ 0xf26fcaa0 ◂— 0
03:0018│-018 0x7ffff26fca28 —▸ 0x504000007910 ◂— '.rsync/localhost:8730/repo/root.cer'
04:0020│-010 0x7ffff26fca30 —▸ 0xffffe4df954 ◂— 0
05:0028│-008 0x7ffff26fca38 —▸ 0x506000007e20 ◂— 0
06:0030│ rbp 0x7ffff26fca40 —▸ 0x7ffff26fcb20 —▸ 0x7ffff26fcd00 —▸ 0x7ffff26fcdd0 ◂— 0
07:0038│+008 0x7ffff26fca48 —▸ 0x5555556043c0 (proc_parser_cert+449) ◂— mov qword ptr [rbp - 0x90], rax
───────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────
 ► 0   0x555555600df2 find_issuer+177
   1   0x5555556043c0 proc_parser_cert+449
   2   0x555555606bf8 parse_entity+1813
   3   0x5555556082db parse_worker+1321
   4   0x7ffff6a94ac3 start_thread+755
   5   0x7ffff6b268c0 clone3+48
───────────────────────────────────────────────────[ THREADS (4 TOTAL) ]───────────────────────────────────────────────────
  ► 5   "rpki-client" stopped: 0x555555600df2 <find_issuer+177> 
    2   "rpki-client" stopped: 0x7ffff6b18c3f <poll+79> 
    3   "rpki-client" stopped: 0x7ffff6a91117 <__futex_abstimed_wait_cancelable64+231> 
    4   "rpki-client" stopped: 0x7ffff6a91117 <__futex_abstimed_wait_cancelable64+231> 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> p mftaki
$1 = 0x504000000250 "28E69049B3B43625D56CFF67F91AE1FBDB70431D"
pwndbg> p aki
$2 = 0x0
pwndbg> p fn
$3 = 0x504000007910 ".rsync/localhost:8730/repo/root.cer"
```

**Rerpoduction Steps：**

This vulnerability is triggered by constructing a certificate lacking the AKI extension and placing it within the Manifest validation process.

Modify the certificate generation logic to remove the code adding the AKI extension. Simultaneously, ensure that the certificate is referenced by a valid Manifest file  so that rpki-client passes the mftaki parameter during parsing.

Generate a repository containing this malformed certificate, then run rpki-client to verify it. The programme immediately crashes, throwing a segmentation fault. The log is as follows:

```shell
rpki-client: ta/fuzz: pulling from rsync://localhost:8730/repo/root.cer
rpki-client: ta/fuzz: loaded from network
rpki-client: ta/fuzz/root.cer: RFC 6487 (trust anchor): pubkey does not match TAL pubkey
rpki-client: .rsync/localhost:8730/repo: pulling from rsync://localhost:8730/repo
rpki-client: .rsync/localhost:8730/repo: loaded from network
rpki-client: localhost:8730/repo/manifest.mft: AKI DA28FA8C5CCBC5B60DCC02C113FD4D98F05B72F2 doesn't match issuer SKI 28E69049B3B43625D56CFF67F91AE1FBDB70431D
AddressSanitizer:DEADLYSIGNAL
=================================================================
==28390==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x72ed52892418 bp 0x72ed4dafca00 sp 0x72ed4dafc180 T3)
==28390==The signal is caused by a READ memory access.
==28390==Hint: address points to the zero page.
    #0 0x72ed52892418  (/lib/x86_64-linux-gnu/libasan.so.6+0x92418)
    #1 0x5a8d0a040e04  (/home/eur1ka/fuzz/rpki-client-9.6/src/rpki-client+0xace04)
    #2 0x5a8d0a0443bf  (/home/eur1ka/fuzz/rpki-client-9.6/src/rpki-client+0xb03bf)
    #3 0x5a8d0a046bf7  (/home/eur1ka/fuzz/rpki-client-9.6/src/rpki-client+0xb2bf7)
    #4 0x5a8d0a0482da  (/home/eur1ka/fuzz/rpki-client-9.6/src/rpki-client+0xb42da)
    #5 0x72ed51e94ac2  (/lib/x86_64-linux-gnu/libc.so.6+0x94ac2)
    #6 0x72ed51f268bf  (/lib/x86_64-linux-gnu/libc.so.6+0x1268bf)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/lib/x86_64-linux-gnu/libasan.so.6+0x92418) 
Thread T3 created by T0 here:
    #0 0x72ed52858685  (/lib/x86_64-linux-gnu/libasan.so.6+0x58685)
    #1 0x5a8d0a048f05  (/home/eur1ka/fuzz/rpki-client-9.6/src/rpki-client+0xb4f05)
    #2 0x5a8d0a029a6d  (/home/eur1ka/fuzz/rpki-client-9.6/src/rpki-client+0x95a6d)
    #3 0x72ed51e29d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)

==28390==ABORTING
rpki-client: parser process exited abnormally
==28404==Can't open /proc/28396/task for reading.
==28396==LeakSanitizer has encountered a fatal error.
==28396==HINT: For debugging, try setting environment variable LSAN_OPTIONS=verbosity=1:log_threads=1
==28396==HINT: LeakSanitizer does not work under ptrace (strace, gdb, etc)
rpki-client: rrdp process exited abnormally
rpki-client: 14 outstanding entities
rpki-client: not all files processed, giving up
==28406==Can't open /proc/28389/task for reading.
==28389==LeakSanitizer has encountered a fatal error.
==28389==HINT: For debugging, try setting environment variable LSAN_OPTIONS=verbosity=1:log_threads=1
==28389==HINT: LeakSanitizer does not work under ptrace (strace, gdb, etc)
```

**Impact:**
Processing a crafted repository containing a certificate missing the AKI extension crashes the parser process.
The failure of a validator signifies the complete cessation of the entire RPKI validation process. Routers will entirely lose their ability to determine the legitimacy of IP prefixes, reverting to the unprotected state prior to RPKI deployment and becoming highly vulnerable to prefix hijacking attacks.
