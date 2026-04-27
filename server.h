#ifndef SERVER_H
#define SERVER_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <winsock.h>

#include "protocol.h"

#define MAX_CLIENTS 100
#define MAX_ROOMS 100

typedef enum state_t {
    CONNECTED,
    AUTHENTICATED,
    IN_ROOM,
    DISCONNECTED
} state_t;

typedef struct client_t {
    int socket;
    char name[50];
    state_t state;
    uint32_t last_active;
    char auth_nonce[65];
    int auth_challenge_sent;
    int failed_attempts;
    SSL *ssl;
} client_t;

typedef struct server_t {
    int server_socket;
    struct sockaddr_in server_addr;
    client_t clients[MAX_CLIENTS];
    int client_count;
    SSL_CTX *ssl_ctx;
} server_t;

typedef enum room_role_t {
    MEMBER,
    MODERATOR,
    OWNER
} room_role_t;

typedef struct room_member_t {
    client_t *client;
    room_role_t role;
} room_member_t;

typedef struct room_t {
    char room_name[50];
    room_member_t members[MAX_CLIENTS];
    int member_count;
    client_t banned_clients[MAX_CLIENTS];
    int banned_count;
} room_t;

typedef struct serverstate_t {
    server_t server;
    room_t rooms[MAX_ROOMS];
    int room_count;
} serverstate_t;

typedef enum command_check {
    VALID_COMMAND,
    INVALID_COMMAND,
    UNKNOWN_COMMAND
} command_check;

void init_server(serverstate_t *state);
void start_server(server_t server);
void handle_client(server_t server, client_t client);
void broadcast_message(server_t server, message_t message);
void send_message(client_t client, message_t message);
int receive_message(client_t client, message_t *message);
void authenticate_client(client_t *client, message_t message);
void join_room(client_t *client, char *room_name);
void leave_room(client_t *client, char *room_name);
void cleanup_client(client_t *client);
void send_private_message(server_t server, client_t sender, message_t message);
void check_command(message_t message, command_check *check, char *arg);
void send_help_message(server_t server, char *client_name);
void show_user_rooms(server_t server, char *client_name, char *arg);
void show_room_users(server_t server, char *client_name, char *arg);
void notify_room_join(client_t *client, char *room_name);
void notify_room_leave(client_t *client, char *room_name);
void store_message(server_t server, char *room_name, message_t message);
void show_messages(server_t server, char *client_name, char *arg);
void acknowledge_message(client_t client, message_t message);
void ban_user_from_room(client_t * client, char *room_name, char *target_name);

#endif