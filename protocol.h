#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#define PORT 8080
#define BUFFER_SIZE 4096

typedef enum type_t {
    LOGIN,
    AUTH_CHALLENGE,
    AUTH_RESPONSE,
    AUTH_RESULT,
    LOGOUT,
    PRIVATE_MESSAGE,
    ROOM_MESSAGE,
    JOIN_ROOM,
    LEAVE_ROOM,
    PING,
    ACK, 
    BAN_USER
} type_t;

typedef struct message_t {
    char sender_name[50];
    char receiver_name[50];
    char content[BUFFER_SIZE];
    type_t type;
    uint16_t length;
    uint8_t flags;
} message_t;

#endif
