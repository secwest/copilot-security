#include <stddef.h>
#include <stdio.h>

typedef void (*emit_audit_fn)(void *context, const char *message);

void audit_login_attempt(const char *remote_username,
                         const char *active_session_secret,
                         emit_audit_fn emit_audit,
                         void *context) {
    if (remote_username == NULL || active_session_secret == NULL ||
        emit_audit == NULL) {
        return;
    }

    char message[256];
    const int written = snprintf(message,
                                 sizeof(message),
                                 remote_username,
                                 active_session_secret);
    if (written < 0) return;

    emit_audit(context, message);
}
