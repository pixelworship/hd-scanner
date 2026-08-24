#include "cbsm.h"

#include <bsm/libbsm.h>
#include <security/audit/audit_ioctl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>

// The file-read audit class. Defined in /etc/security/audit_class as
// "0x00000001:fr:file read"; there is no header constant for it.
#define HDW_AUDIT_CLASS_FILE_READ 0x00000001

int hdw_bsm_parse_record(const uint8_t *buf, size_t len, HDWBsmRead *out) {
    memset(out, 0, sizeof(*out));
    out->success = 1;               // assume success unless a return token says otherwise
    int has_path = 0;

    int remaining = (int)len;
    u_char *p = (u_char *)buf;

    while (remaining > 0) {
        tokenstr_t tok;
        if (au_fetch_tok(&tok, p, remaining) != 0) break;

        switch (tok.id) {
        case AUT_HEADER32:
            out->event = tok.tt.hdr32.e_type;
            out->seconds = (int64_t)tok.tt.hdr32.s;
            break;
        case AUT_HEADER64:
            out->event = tok.tt.hdr64.e_type;
            out->seconds = (int64_t)tok.tt.hdr64.s;
            break;
        case AUT_HEADER32_EX:
            out->event = tok.tt.hdr32_ex.e_type;
            out->seconds = (int64_t)tok.tt.hdr32_ex.s;
            break;
        case AUT_HEADER64_EX:
            out->event = tok.tt.hdr64_ex.e_type;
            out->seconds = (int64_t)tok.tt.hdr64_ex.s;
            break;
        case AUT_PATH: {
            // A record can carry more than one path token (openat gives the
            // argument and then the resolved path); the last is the fully
            // resolved one, so later tokens deliberately overwrite earlier.
            size_t n = tok.tt.path.len;
            if (n >= sizeof(out->path)) n = sizeof(out->path) - 1;
            memcpy(out->path, tok.tt.path.path, n);
            out->path[n] = 0;
            out->path[strlen(out->path)] = 0;   // trim at the token's own NUL
            has_path = 1;
            break;
        }
        case AUT_SUBJECT32:
            out->pid = (int32_t)tok.tt.subj32.pid;
            out->euid = tok.tt.subj32.euid;
            break;
        case AUT_SUBJECT64:
            out->pid = (int32_t)tok.tt.subj64.pid;
            out->euid = tok.tt.subj64.euid;
            break;
        case AUT_SUBJECT32_EX:
            out->pid = (int32_t)tok.tt.subj32_ex.pid;
            out->euid = tok.tt.subj32_ex.euid;
            break;
        case AUT_SUBJECT64_EX:
            out->pid = (int32_t)tok.tt.subj64_ex.pid;
            out->euid = tok.tt.subj64_ex.euid;
            break;
        case AUT_RETURN32:
            out->success = (tok.tt.ret32.status == 0);
            break;
        case AUT_RETURN64:
            out->success = (tok.tt.ret64.err == 0);
            break;
        default:
            break;
        }

        if (tok.len == 0) break;    // malformed; do not spin
        p += tok.len;
        remaining -= tok.len;
    }
    return has_path ? 1 : 0;
}

int hdw_auditpipe_configure(int fd) {
    // Do not drop records under bursts: take the largest queue the kernel
    // allows.
    unsigned int qmax = 0;
    if (ioctl(fd, AUDITPIPE_GET_QLIMIT_MAX, &qmax) == 0 && qmax > 0) {
        (void)ioctl(fd, AUDITPIPE_SET_QLIMIT, &qmax);
    }

    // Local preselection: this pipe chooses its own classes, independent of the
    // system-wide audit configuration (which does not select file reads).
    int mode = AUDITPIPE_PRESELECT_MODE_LOCAL;
    if (ioctl(fd, AUDITPIPE_SET_PRESELECT_MODE, &mode) != 0) return -errno;

    au_mask_t mask;
    mask.am_success = HDW_AUDIT_CLASS_FILE_READ;
    mask.am_failure = HDW_AUDIT_CLASS_FILE_READ;
    if (ioctl(fd, AUDITPIPE_SET_PRESELECT_FLAGS, &mask) != 0) return -errno;
    // Also select reads by processes with no audit user id (system daemons).
    if (ioctl(fd, AUDITPIPE_SET_PRESELECT_NAFLAGS, &mask) != 0) return -errno;

    return 0;
}

unsigned long long hdw_auditpipe_drops(int fd) {
    unsigned long long drops = 0;
    if (ioctl(fd, AUDITPIPE_GET_DROPS, &drops) != 0) return 0;
    return drops;
}
