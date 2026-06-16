/*
 * scanner_service.c - user-mode companion to avfilter.sys.
 *
 * Connects to the minifilter's communication port, receives a file path for
 * every open, runs detection, and replies clean/infected so the kernel can
 * block the open.
 *
 * Detection here is REAL (no longer a stub): it computes the file's SHA-256 and
 * checks it against the abuse.ch-derived blocklist (data/hashes.txt) that the
 * Python engine maintains, plus the standard EICAR test hash so you can verify
 * the whole driver->service->block pipeline safely. This mirrors the hash path
 * in engine/scanners.py; YARA can be layered on the same way.
 *
 * Build in a Windows VM with the WDK/MSVC (this file does not compile without
 * them - it needs fltuser.h and bcrypt.h):
 *
 *   cl scanner_service.c /link fltlib.lib bcrypt.lib
 *
 * Run elevated (the filter port is admin-only by default). Point it at the
 * blocklist with the EYIL_HASHES env var, or it falls back to ..\data\hashes.txt.
 */

#include <windows.h>
#include <fltuser.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <ctype.h>

#define HASH_HEX_LEN 64
#define SERVICE_NAME L"EyilGuardScan"

#include "avscan_protocol.h"

typedef struct _AV_MESSAGE {
    FILTER_MESSAGE_HEADER Header;
    AV_SCAN_REQUEST       Request;
} AV_MESSAGE, *PAV_MESSAGE;

typedef struct _AV_REPLY {
    FILTER_REPLY_HEADER Header;
    AV_SCAN_REPLY       Reply;
} AV_REPLY, *PAV_REPLY;

/* SHA-256 of the standard EICAR test file - always flagged so the pipeline is
 * verifiable without real malware. */
static const char EICAR_SHA256[] =
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

/* ---- blocklist (sorted array of lowercase 64-hex strings, bsearch'd) ---- */

static char (*g_hashes)[HASH_HEX_LEN + 1] = NULL;
static size_t g_count = 0;
static WCHAR g_hash_path[MAX_PATH] = L"";
static HANDLE g_port = INVALID_HANDLE_VALUE;
static SERVICE_STATUS_HANDLE g_service_status_handle = NULL;
static SERVICE_STATUS g_service_status = {0};

static int hash_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int is_hex64(const char *s)
{
    if (strlen(s) != HASH_HEX_LEN) return 0;
    for (int i = 0; i < HASH_HEX_LEN; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

/* Load data/hashes.txt (or %EYIL_HASHES%) into the sorted blocklist. */
static void LoadBlocklist(void)
{
    char path[MAX_PATH];
    if (g_hash_path[0]) {
        size_t converted = 0;
        if (wcstombs_s(&converted, path, sizeof(path), g_hash_path, _TRUNCATE) != 0)
            strcpy_s(path, sizeof(path), "..\\data\\hashes.txt");
    } else {
        DWORD n = GetEnvironmentVariableA("EYIL_HASHES", path, sizeof(path));
        if (n == 0 || n >= sizeof(path))
            strcpy_s(path, sizeof(path), "..\\data\\hashes.txt");
    }

    FILE *f = NULL;
    if (fopen_s(&f, path, "r") != 0 || !f) {
        wprintf(L"[blocklist] could not open %hs - hash detection limited to EICAR\n", path);
        fflush(stdout);
        return;
    }

    size_t cap = 1024;
    g_hashes = malloc(cap * (HASH_HEX_LEN + 1));
    char line[256];
    while (g_hashes && fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r' || line[len - 1] == ' '))
            line[--len] = '\0';
        for (size_t i = 0; i < len; i++) line[i] = (char)tolower((unsigned char)line[i]);
        if (line[0] == '#' || !is_hex64(line)) continue;
        if (g_count == cap) {
            cap *= 2;
            void *grown = realloc(g_hashes, cap * (HASH_HEX_LEN + 1));
            if (!grown) break;
            g_hashes = grown;
        }
        memcpy(g_hashes[g_count], line, HASH_HEX_LEN + 1);
        g_count++;
    }
    fclose(f);
    if (g_hashes && g_count)
        qsort(g_hashes, g_count, HASH_HEX_LEN + 1, hash_cmp);
    wprintf(L"[blocklist] loaded %zu known-bad hashes from %hs\n", g_count, path);
    fflush(stdout);
}

static BOOL InBlocklist(const char *hex)
{
    if (strcmp(hex, EICAR_SHA256) == 0) return TRUE;
    if (!g_hashes || g_count == 0) return FALSE;
    return bsearch(hex, g_hashes, g_count, HASH_HEX_LEN + 1, hash_cmp) != NULL;
}

/* ---- SHA-256 of a file via CNG (BCrypt) -------------------------------- */

static BOOL ComputeSha256Hex(const WCHAR *path, char out[HASH_HEX_LEN + 1])
{
    WCHAR openPath[AV_MAX_PATH + 32];

    if (wcsncmp(path, L"\\Device\\", 8) == 0) {
        if (swprintf_s(openPath, _countof(openPath), L"\\\\?\\GLOBALROOT%s", path) < 0)
            return FALSE;
    } else {
        if (wcscpy_s(openPath, _countof(openPath), path) != 0)
            return FALSE;
    }

    HANDLE file = CreateFileW(openPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;

    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BOOL ok = FALSE;
    BYTE digest[32];

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) goto done;
    if (BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0) != 0) goto done;

    BYTE buf[65536];
    DWORD read = 0;
    while (ReadFile(file, buf, sizeof(buf), &read, NULL) && read > 0) {
        if (BCryptHashData(hash, buf, read, 0) != 0) goto done;
    }
    if (BCryptFinishHash(hash, digest, sizeof(digest), 0) != 0) goto done;

    for (int i = 0; i < 32; i++)
        sprintf_s(out + i * 2, 3, "%02x", digest[i]);
    out[HASH_HEX_LEN] = '\0';
    ok = TRUE;

done:
    if (hash) BCryptDestroyHash(hash);
    if (alg)  BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(file);
    return ok;
}

/* ---- The detection decision ------------------------------------------- */

static BOOL ScanIsInfected(const WCHAR *path)
{
    char hex[HASH_HEX_LEN + 1];
    if (!ComputeSha256Hex(path, hex))
        return FALSE;               /* fail open: never block on a read error */
    return InBlocklist(hex);
}

static DWORD RunScannerLoop(void)
{
    HRESULT hr;

    LoadBlocklist();

    hr = FilterConnectCommunicationPort(AV_PORT_NAME, 0, NULL, 0, NULL, &g_port);
    if (FAILED(hr)) {
        wprintf(L"Could not connect to %s (0x%08x). "
                L"Is the driver loaded and are you elevated?\n",
                AV_PORT_NAME, hr);
        return 1;
    }
    wprintf(L"Connected. Waiting for scan requests...\n");
    fflush(stdout);

    for (;;) {
        AV_MESSAGE msg = {0};

        hr = FilterGetMessage(g_port, &msg.Header, sizeof(msg), NULL);
        if (FAILED(hr)) {
            wprintf(L"FilterGetMessage failed: 0x%08x\n", hr);
            fflush(stdout);
            break;
        }

        /* Ensure null termination before using the path as a string. */
        ULONG chars = msg.Request.PathLength / sizeof(WCHAR);
        if (chars >= AV_MAX_PATH) chars = AV_MAX_PATH - 1;
        msg.Request.Path[chars] = L'\0';

        BOOL infected = ScanIsInfected(msg.Request.Path);
        wprintf(L"%s  ->  %s\n", msg.Request.Path,
                infected ? L"INFECTED (blocking)" : L"clean");
        fflush(stdout);

        /* Reply to the kernel with our verdict. */
        AV_REPLY rep = {0};
        rep.Header.Status = 0;
        rep.Header.MessageId = msg.Header.MessageId;
        rep.Reply.Infected = (BOOLEAN)(infected ? TRUE : FALSE);

        hr = FilterReplyMessage(g_port, &rep.Header,
                                sizeof(FILTER_REPLY_HEADER) + sizeof(AV_SCAN_REPLY));
        if (FAILED(hr)) {
            wprintf(L"FilterReplyMessage failed: 0x%08x\n", hr);
            fflush(stdout);
        }
    }

    if (g_hashes) free(g_hashes);
    if (g_port != INVALID_HANDLE_VALUE) {
        CloseHandle(g_port);
        g_port = INVALID_HANDLE_VALUE;
    }
    return 0;
}

static void ReportStatus(DWORD state, DWORD exit_code, DWORD wait_hint)
{
    if (!g_service_status_handle) return;
    g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_service_status.dwCurrentState = state;
    g_service_status.dwWin32ExitCode = exit_code;
    g_service_status.dwWaitHint = wait_hint;
    g_service_status.dwControlsAccepted =
        (state == SERVICE_RUNNING) ? SERVICE_ACCEPT_STOP : 0;
    SetServiceStatus(g_service_status_handle, &g_service_status);
}

static void WINAPI ServiceCtrlHandler(DWORD control)
{
    if (control != SERVICE_CONTROL_STOP) return;
    ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 2000);
    if (g_port != INVALID_HANDLE_VALUE) {
        CloseHandle(g_port);
        g_port = INVALID_HANDLE_VALUE;
    }
}

static void WINAPI ServiceMain(DWORD argc, LPWSTR *argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    g_service_status_handle = RegisterServiceCtrlHandlerW(SERVICE_NAME, ServiceCtrlHandler);
    if (!g_service_status_handle) return;
    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 2000);
    ReportStatus(SERVICE_RUNNING, NO_ERROR, 0);
    DWORD rc = RunScannerLoop();
    ReportStatus(SERVICE_STOPPED, rc, 0);
}

static void ParseArgs(int argc, wchar_t **argv, BOOL *service_mode)
{
    *service_mode = FALSE;
    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"--service") == 0) {
            *service_mode = TRUE;
        } else if (_wcsicmp(argv[i], L"--hashes") == 0 && i + 1 < argc) {
            wcscpy_s(g_hash_path, _countof(g_hash_path), argv[++i]);
        }
    }
}

int wmain(int argc, wchar_t **argv)
{
    BOOL service_mode = FALSE;
    ParseArgs(argc, argv, &service_mode);
    if (service_mode) {
        SERVICE_TABLE_ENTRYW table[] = {
            { SERVICE_NAME, ServiceMain },
            { NULL, NULL }
        };
        if (!StartServiceCtrlDispatcherW(table)) {
            wprintf(L"StartServiceCtrlDispatcher failed: %lu\n", GetLastError());
            fflush(stdout);
            return 1;
        }
        return 0;
    }
    return (int)RunScannerLoop();
}
