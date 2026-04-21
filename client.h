#ifndef CLIENT_H
#define CLIENT_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <winsock.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "protocol.h"

typedef struct client_connection_t {
    int socket;
    struct sockaddr_in server_addr;
    char name[50];
    SSL *ssl; // SSL context for this client
} client_connection_t;

void init_client(client_connection_t *client, const char *server_ip, int port);
void run_client(client_connection_t *client);
void send_message_to_server(client_connection_t *client, const message_t *message);
int receive_message_from_server(client_connection_t *client, message_t *message);
void send_to_room(client_connection_t *client, const char* room_name, const char* message);
void leave_room(client_connection_t *client, const char* room_name);
void join_room(client_connection_t *client, const char* room_name);

#endif
