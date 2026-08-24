// A thin C shim over Apple's OpenBSM library (libbsm), used to read file-read
// events from /dev/auditpipe.
//
// The audit pipe is the one mechanism short of Endpoint Security that reports
// *every* open()-for-read on the system as it happens — including a process
// that opens, reads and closes a file in under a millisecond, which descriptor
// sampling can never catch. It needs root, which the daemon has.
//
// libbsm's own token walker (au_fetch_tok, the same code praudit uses) does the
// parsing, so this shim only extracts the few fields a read event needs. Its
// deprecation warnings are contained to this file.
#ifndef HDW_CBSM_H
#define HDW_CBSM_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint16_t event;         // BSM event type (e.g. AUE_OPEN_R)
    int32_t  pid;
    uint32_t euid;
    int64_t  seconds;       // record timestamp, seconds since epoch
    int32_t  success;       // 1 when the syscall succeeded
    char     path[1024];    // resolved path, NUL-terminated, truncated to fit
} HDWBsmRead;

// Parses one raw audit record. Returns 1 and fills `out` when the record
// carries a file path (i.e. it is a file event); 0 otherwise.
int hdw_bsm_parse_record(const uint8_t *buf, size_t len, HDWBsmRead *out);

// Configures an already-open /dev/auditpipe descriptor: raises the queue limit
// to its maximum, switches to local preselection, and selects the file-read
// class for both attributable and non-attributable events. Returns 0, or a
// negative errno. Kept in C so the ioctl numbers and au_mask_t never have to be
// reconstructed on the Swift side.
int hdw_auditpipe_configure(int fd);

#endif
