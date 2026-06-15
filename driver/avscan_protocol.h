/*
 * Shared kernel <-> user-mode scan protocol.
 *
 * Keep this intentionally small. The minifilter should enforce decisions, not
 * run expensive AV logic in kernel mode.
 */

#pragma once

#define AV_PORT_NAME L"\\AvScanPort"
#define AV_MAX_PATH 1024

typedef struct _AV_SCAN_REQUEST {
    ULONG PathLength;
    WCHAR Path[AV_MAX_PATH];
} AV_SCAN_REQUEST, *PAV_SCAN_REQUEST;

typedef struct _AV_SCAN_REPLY {
    BOOLEAN Infected;
} AV_SCAN_REPLY, *PAV_SCAN_REPLY;
