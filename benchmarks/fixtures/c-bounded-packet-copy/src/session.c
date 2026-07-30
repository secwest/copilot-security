#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct login_session {
    char username[32];
    uint8_t is_admin;
};

_Static_assert(offsetof(struct login_session, is_admin) == 32,
               "benchmark requires adjacent authorization state");

typedef void (*grant_admin_fn)(void *peer);

static uint16_t read_u16_be(const uint8_t *bytes) {
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static int parse_login_packet(struct login_session *session,
                              const uint8_t *packet,
                              size_t packet_size) {
    if (packet_size < 2) return -1;

    const uint16_t username_length = read_u16_be(packet);
    if ((size_t)username_length > packet_size - 2) return -1;
    if ((size_t)username_length >= sizeof(session->username)) return -1;

    memcpy(session->username, packet + 2, username_length);
    session->username[username_length] = '\0';
    return 0;
}

void handle_login_packet(const uint8_t *packet,
                         size_t packet_size,
                         grant_admin_fn grant_admin,
                         void *peer) {
    struct login_session session = {0};
    if (parse_login_packet(&session, packet, packet_size) != 0) return;

    if (session.is_admin != 0) {
        grant_admin(peer);
    }
}
