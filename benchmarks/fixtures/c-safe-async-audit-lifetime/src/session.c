#include <stddef.h>
#include <string.h>

typedef void (*send_report_fn)(void *peer, const char *report);

struct session {
    int is_admin;
    send_report_fn send_report;
    void *peer;
};

union session_slot {
    max_align_t alignment;
    unsigned char bytes[sizeof(struct session)];
};

static union session_slot slot;
static int slot_in_use;
static struct session *pending_audit_session;

static struct session *acquire_session(void) {
    if (slot_in_use) return NULL;
    slot_in_use = 1;
    memset(slot.bytes, 0, sizeof(slot.bytes));
    return (struct session *)(void *)slot.bytes;
}

static void release_session(struct session *session) {
    if (session != (struct session *)(void *)slot.bytes) return;
    memset(slot.bytes, 0xdd, sizeof(slot.bytes));
    slot_in_use = 0;
}

struct session *session_open(int is_admin,
                             send_report_fn send_report,
                             void *peer) {
    struct session *session = acquire_session();
    if (session == NULL || send_report == NULL) return NULL;
    session->is_admin = is_admin;
    session->send_report = send_report;
    session->peer = peer;
    return session;
}

int begin_admin_audit(struct session *session) {
    if (session == NULL || !session->is_admin) return -1;
    pending_audit_session = session;
    return 0;
}

void session_close(struct session *session) {
    if (pending_audit_session == session) {
        pending_audit_session = NULL;
    }
    release_session(session);
}

void complete_admin_audit(const char *report) {
    if (pending_audit_session == NULL || report == NULL) return;
    pending_audit_session->send_report(pending_audit_session->peer, report);
    pending_audit_session = NULL;
}
