# ClamAV 1.5.2 Security & Quality Audit Changelog

Date: 2026-03-06
Scope: Memory safety, CPU/DoS, bug fixes, security hardening

---

## CRITICAL / HIGH Severity

### [M1] libclamav/htmlnorm.c — Uninitialized pointer free after realloc

Initialize new realloc'd slots to NULL to prevent freeing garbage pointers during cleanup.

```diff
  tags->tag = tmp;
+ tags->tag[tagCnt] = NULL;
  tagCnt++;

  tags->value = tmp;
+ tags->value[valueCnt] = NULL;
  valueCnt++;
```

### [M2] libclamav/disasm.c — Unbounded sprintf in spam_x86

Added buffer size parameter and replaced all `sprintf`/`strcpy` with `snprintf`.

```diff
- static void spam_x86(struct DISASMED *s, char *hr)
+ static void spam_x86(struct DISASMED *s, char *hr, size_t hrsz)
  {
-     strcpy(hr, "?? ");
+     snprintf(hr, hrsz, "?? ");
      ...
-     sprintf(hr, "%s%s", pushed, x86regs[s->real_op1.reg]);
+     snprintf(hr, hrsz, "%s%s", pushed, x86regs[s->real_op1.reg]);
      ...
  }

  // Caller updated:
- spam_x86(&s, hr);
+ spam_x86(&s, hr, sizeof(hr));
```

### [M3] libclamav/scanners.c — Leaked hash_string on fmap_get_hash failure

```diff
  if (CL_SUCCESS != ret || hash == NULL) {
      cli_errmsg("scan_common: fmap_get_hash failed: %d\n", ret);
+     free(hash_string);
      status = ret;
```

### [M4] common/output.c — strftime offset computed without validating .log suffix

```diff
+ size_t rf_len      = strlen(rotate_file);
+ size_t suffix_len  = strlen(".log");
+ size_t strftime_at;
+ if (rf_len >= suffix_len && strcmp(rotate_file + rf_len - suffix_len, ".log") == 0) {
+     strftime_at = rf_len - suffix_len;
+ } else {
+     strftime_at = rf_len;
+ }
- strftime(rotate_file + strlen(rotate_file) - 4, ...);
+ strftime(rotate_file + strftime_at, rotate_file_len - strftime_at + 1,
+          "-%Y%m%d_%H%M%S.log", &tmp);
```

### [M5] libclamav/crypto.c — Off-by-one in authority cleanup loop

Pre-decrement instead of post-decrement to avoid skipping last element / reading index -1.

```diff
  while (nauths > 0)
-     free(authorities[nauths--]);
+     free(authorities[--nauths]);
  free(authorities);
```

### [C1] libclamav/htmlnorm.c — No time limit check in HTML normalization loop

```diff
  while (line) {
+     if (ctx && cli_checktimelimit(ctx) != CL_SUCCESS) {
+         cli_dbgmsg("cli_html_normalise: Time limit reached\n");
+         goto done;
+     }
```

### [C2] libclamav/yara_exec.c — 128KB stack allocation in threaded code

Converted YARA evaluation stack from stack-allocated to heap-allocated.

```diff
- int64_t stack[STACK_SIZE];
+ int64_t *stack = NULL;
+
+ stack = malloc(STACK_SIZE * sizeof(int64_t));
+ if (!stack) {
+     cli_errmsg("yr_execute_code: failed to allocate stack\n");
+     return CL_EMEM;
+ }

  // All 6 return paths converted to:
- return ERROR_xxx;
+ result = ERROR_xxx;
+ goto yr_cleanup;

  // Cleanup label added:
+ yr_cleanup:
+     free(stack);
+     return result;
```

---

## HIGH Severity Bugs

### [B1] libclamav/readdb.c — Writing through const char* pointer

Rewrote `cli_virname` to use `memcpy` with computed length instead of modifying a const string.

```diff
- pt = strstr(virname, " (Clam)");
- if (pt) {
-     *pt = 0;  /* UB: writing through const pointer */
-     ...
- }
- newname = cli_safer_strdup(virname);
- strcat(newname, ".UNOFFICIAL");
+ pt = strstr(virname, " (Clam)");
+ namelen = pt ? (size_t)(pt - virname) : strlen(virname);
+ newname = (char *)cli_max_malloc(namelen + sizeof(".UNOFFICIAL"));
+ if (!newname) ...
+ memcpy(newname, virname, namelen);
+ memcpy(newname + namelen, ".UNOFFICIAL", 12);
```

### [B2] clamd/session.c — NULL dereference from cli_ctime

```diff
- tstr = cli_ctime(&t, timestr, sizeof(timestr));
- tlen = strlen(tstr);
- tstr[tlen - 1] = '\0';
+ tstr = cli_ctime(&t, timestr, sizeof(timestr));
+ if (!tstr) {
+     tstr = "unknown";
+ } else {
+     tlen = strlen(tstr);
+     if (tlen > 0 && tstr[tlen - 1] == '\n')
+         timestr[tlen - 1] = '\0';
+ }
```

### [B3] clamd/server-th.c, server.h, scanner.c — Unsafe signal handler + non-volatile globals

Replaced `logg()` in signal handler with async-signal-safe `write()`, declared globals as `volatile sig_atomic_t`.

```diff
  // server-th.c
- int progexit = 0;
- int reload = 0;
+ volatile sig_atomic_t progexit = 0;
+ volatile sig_atomic_t reload = 0;
+ volatile sig_atomic_t sighup = 0;

  void sighandler(int sig) {
-     logg("*Signal %d caught, trying to exit\n", sig);
+     const char msg[] = "Signal caught, trying to exit\n";
+     (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
      progexit = 1;
  }

  // server.h
+ #include <signal.h>
- extern int progexit, reload;
+ extern volatile sig_atomic_t progexit, reload;

  // scanner.c
- extern int progexit;
+ extern volatile sig_atomic_t progexit;
```

---

## MEDIUM Severity Bugs

### [B4] common/optparser.c — Leaked nextarg nodes without strarg

```diff
  while (a) {
-     if (a->strarg) {
-         free(a->name);
-         free(a->cmd);
-         free(a->strarg);
-         h = a;
-         a = a->nextarg;
-         free(h);
-     }
+     free(a->name);
+     free(a->cmd);
+     free(a->strarg);
+     h = a;
+     a = a->nextarg;
+     free(h);
  }
```

### [B5] clamd/session.c — Leaked filename on dup_conn error

```diff
  if (!dup_conn) {
+     free(dup_conn->filename);
      free(dup_conn);
      ...
  }
```

### [B7] libclamav/matcher.c — Unsigned underflow in EOF_MINUS/EP_MINUS offsets

```diff
  case CLI_OFF_EOF_MINUS:
-     *offset_min = info->fsize - offdata[1];
+     if (offdata[1] > info->fsize)
+         *offset_min = CLI_OFF_NONE;
+     else
+         *offset_min = info->fsize - offdata[1];
      break;

  case CLI_OFF_EP_MINUS:
-     *offset_min = info->exeinfo.ep - offdata[1];
+     if (offdata[1] > info->exeinfo.ep)
+         *offset_min = CLI_OFF_NONE;
+     else
+         *offset_min = info->exeinfo.ep - offdata[1];
      break;
```

### [B8] clamscan/manager.c — Dangling pointer: free before unlink

```diff
- free(filename);
- unlink(filename);   /* use-after-free */
+ unlink(filename);
+ free(filename);
```

### [B9] libclamav/matcher.c — perf_log_filter parameter type mismatch

```diff
  #ifdef CLI_PERF_LOGGING
- static inline void perf_log_filter(int32_t pos, int32_t length, int8_t trie)
+ static inline void perf_log_filter(int32_t pos, uint32_t length, int8_t trie)
  // Now matches the non-perf stub: (int32_t pos, uint32_t length, int8_t trie)
```

---

## MEDIUM Severity Security

### [S3] libclamav/pdf.c — Octal escape accepts invalid digits 8/9

```diff
  // PDF spec: octal escapes use digits 0-7 only
- case '8':
- case '9':
  case '0':
  case '1':
  ...
  case '7':
-     octal = str[i] - '0';
-     if (...) { octal = octal * 8 + (str[i+1] - '0'); ... }
-     if (...) { octal = octal * 8 + (str[i+2] - '0'); ... }
+     {
+         unsigned octal = 0;
+         int j;
+         for (j = 0; j < 3 && (i + j) < dict_length; j++) {
+             char c = str[i + j];
+             if (c < '0' || c > '7')
+                 break;
+             octal = octal * 8 + (c - '0');
+         }
+         octal &= 0xff;
+         decoded[newlen++] = (char)octal;
+         i += j - 1;
+     }
```

### [S4] libclamav/elf.c — Integer overflow in virtual address range checks

```diff
  // cli_rawaddr32 and cli_rawaddr64:
- if (vaddr >= p_vaddr && p_vaddr + p_memsz > vaddr) {
+ if (vaddr >= p_vaddr && (vaddr - p_vaddr) < p_memsz) {
      // Overflow-safe: subtraction can't wrap when vaddr >= p_vaddr
```

### [S5] libclamav/pdf.c — Out-of-bounds read in hex escape with dict_length < 2

```diff
+ if (dict_length < 2)
+     break;
  for (i = 0; i < dict_length - 2; i++) {
```

### [S6] libclamav/stats_json.c — Unbounded sprintf for JSON serialization

```diff
- sprintf(buf, "{\n\t\"hostid\": \"%s\",\n", hostid);
+ buf = ensure_bufsize(buf, &bufsz, curused, strlen(hostid) + 30);
+ if (!(buf))
+     return NULL;
+ snprintf(buf + curused, bufsz - curused, "{\n\t\"hostid\": \"%s\",\n", hostid);
+ curused = strlen(buf);
```

---

## MEDIUM Severity CPU / DoS

### [C6] libclamav/yara_exec.c, yara_exec.h, matcher.c — No timeout in YARA bytecode VM

```diff
  // yara_exec.h
+ struct cli_ctx_tag;
- int yr_execute_code(...);
+ int yr_execute_code(..., struct cli_ctx_tag *clamctx);

  // yara_exec.c
+ static int yr_op_count = 0;
  while (!stop) {
+     if (++yr_op_count % 10 == 0 && clamctx &&
+         cli_checktimelimit(clamctx) != CL_SUCCESS) {
+         cli_dbgmsg("yr_execute_code: time limit reached\n");
+         result = ERROR_SUCCESS;
+         goto yr_cleanup;
+     }

  // matcher.c (caller)
- yr_execute_code(ac_lsig, acdata, ctx, &context, 0, 0);
+ yr_execute_code(ac_lsig, acdata, ctx, &context, 0, 0, ctx);
```

### [C7] libclamav/jpeg.c — No segment limit or timeout in JPEG parser

```diff
+ #include "others.h"
+ #define MAX_JPEG_SEGMENTS 65536

  while (1) {
+     if (++segment_count > MAX_JPEG_SEGMENTS) {
+         cli_dbgmsg("cli_parsejpeg: segment limit reached\n");
+         break;
+     }
+     if (ctx && cli_checktimelimit(ctx) != CL_SUCCESS) {
+         cli_dbgmsg("cli_parsejpeg: time limit reached\n");
+         break;
+     }
```

### [C8] libclamav/matcher.c, scanners.c, fmap.c — sprintf in hash-to-hex hot path

Replaced unbounded `sprintf` with bounded `snprintf` at 6 hash conversion sites.

```diff
  for (i = 0; i < hash_len; i++) {
-     sprintf(hash_string + i * 2, "%02x", hash[i]);
+     snprintf(hash_string + i * 2, 3, "%02x", hash[i]);
  }
```

Files changed: matcher.c:639, scanners.c:4651, scanners.c:6100, fmap.c:1162, fmap.c:1278, fmap.c:1596

---

## MEDIUM Severity Memory (New Findings)

### [MN1] libclamav/7z_iface.c — Write error silently overwritten by scan result

```diff
  if (cli_writen(fd, outBuffer + offset, outSizeProcessed) != outSizeProcessed) {
      found = CL_EWRITE;
- }
- found = cli_magic_scan_desc(fd, tmp_name, ctx, name, LAYER_ATTRIBUTES_NONE);
+ } else {
+     found = cli_magic_scan_desc(fd, tmp_name, ctx, name, LAYER_ATTRIBUTES_NONE);
+ }
```

### [MN2] libclamav/rtf.c — Swapped statements make bread advancement a no-op

```diff
  case WAIT_ZERO: {
      if (out_cnt < 8 - data->bread) {
-         out_cnt = 0;
-         data->bread += out_cnt;  /* always adds 0 */
+         data->bread += out_cnt;  /* must come BEFORE zeroing */
+         out_cnt = 0;
```

---

## Skipped (By Design / Won't Fix)

### [S1] HIGH — Command injection via %v log format (user decision: security ignored)
### [S2] HIGH — freshclam execute callback (user decision: security ignored)
### [C5] MEDIUM — Thread pool single-mutex (standard condition-variable pattern, by design)
### [C9] MEDIUM — thrmgr_printstats holds pools_lock during I/O (necessary to prevent pool free during traversal)

---

## Summary

| Category | Fixed | Skipped | Total |
|----------|-------|---------|-------|
| Memory   | 7 (M1-M5, MN1, MN2) | 0 | 7 |
| Security | 4 (S3-S6) | 2 (S1-S2) | 6 |
| Bugs     | 7 (B1-B5, B7-B9) | 0 | 7 |
| CPU/DoS  | 5 (C1-C2, C6-C8) | 2 (C5, C9) | 7 |
| **Total**| **23** | **4** | **27** |

### Files Modified (22 files)

| File | Fixes Applied |
|------|---------------|
| libclamav/htmlnorm.c | M1, C1 |
| libclamav/disasm.c | M2 |
| libclamav/scanners.c | M3, C8 |
| common/output.c | M4 |
| libclamav/crypto.c | M5 |
| common/optparser.c | B4 |
| clamd/session.c | B2, B5 |
| clamscan/manager.c | B8 |
| libclamav/readdb.c | B1 |
| clamd/server-th.c | B3 |
| clamd/server.h | B3 |
| clamd/scanner.c | B3 |
| libclamav/yara_exec.c | C2, C6 |
| libclamav/yara_exec.h | C6 |
| libclamav/matcher.c | B7, B9, C6, C8 |
| libclamav/jpeg.c | C7 |
| libclamav/pdf.c | S3, S5 |
| libclamav/elf.c | S4 |
| libclamav/stats_json.c | S6 |
| libclamav/7z_iface.c | MN1 |
| libclamav/rtf.c | MN2 |
| libclamav/fmap.c | C8 |
