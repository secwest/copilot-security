#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef void (*send_report_fn)(void *peer, const char *report);
typedef uint64_t session_handle;

struct session {
    session_handle handle;
    unsigned int references;
    int closed;
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
static session_handle next_handle = 1;
static struct session *pending_audit_session;
static atomic_flag state_lock = ATOMIC_FLAG_INIT;

static void lock_state(void) {
    while (atomic_flag_test_and_set_explicit(&state_lock,
                                             memory_order_acquire)) {
    }
}

static void unlock_state(void) {
    atomic_flag_clear_explicit(&state_lock, memory_order_release);
}

static struct session *slot_session(void) {
    return (struct session *)(void *)slot.bytes;
}

static int is_live_handle(session_handle handle) {
    return handle != 0 && slot_in_use && slot_session()->handle == handle;
}

static void release_reference_locked(struct session *session) {
    if (!slot_in_use || session != slot_session() || session->references == 0) {
        return;
    }
    session->references--;
    if (session->references != 0) return;
    memset(slot.bytes, 0xdd, sizeof(slot.bytes));
    slot_in_use = 0;
}

session_handle session_open(int is_admin,
                            send_report_fn send_report,
                            void *peer) {
    if (send_report == NULL) return 0;
    lock_state();
    if (slot_in_use || next_handle == 0) {
        unlock_state();
        return 0;
    }
    const session_handle handle = next_handle;
    next_handle = handle == UINT64_MAX ? 0 : handle + 1;
    slot_in_use = 1;
    memset(slot.bytes, 0, sizeof(slot.bytes));
    struct session *session = slot_session();
    session->handle = handle;
    session->references = 1;
    session->is_admin = is_admin;
    session->send_report = send_report;
    session->peer = peer;
    unlock_state();
    return handle;
}

int begin_admin_audit(session_handle handle) {
    lock_state();
    if (!is_live_handle(handle)) {
        unlock_state();
        return -1;
    }
    struct session *session = slot_session();
    if (session->closed || !session->is_admin ||
        pending_audit_session != NULL) {
        unlock_state();
        return -1;
    }
    session->references++;
    pending_audit_session = session;
    unlock_state();
    return 0;
}

void session_close(session_handle handle) {
    lock_state();
    if (!is_live_handle(handle)) {
        unlock_state();
        return;
    }
    struct session *session = slot_session();
    if (session->closed) {
        unlock_state();
        return;
    }
    session->closed = 1;
    if (pending_audit_session == session) {
        pending_audit_session = NULL;
        release_reference_locked(session);
    }
    release_reference_locked(session);
    unlock_state();
}

void complete_admin_audit(const char *report) {
    if (report == NULL) return;
    lock_state();
    struct session *session = pending_audit_session;
    pending_audit_session = NULL;
    if (session == NULL) {
        unlock_state();
        return;
    }
    if (session->closed) {
        release_reference_locked(session);
        unlock_state();
        return;
    }

    send_report_fn send_report = session->send_report;
    void *peer = session->peer;
    unlock_state();

    send_report(peer, report);

    lock_state();
    release_reference_locked(session);
    unlock_state();
}
