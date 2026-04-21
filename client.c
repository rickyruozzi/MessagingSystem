#include "client.h"

void init_client(client_connection_t *client, const char *server_ip, int port){
    client->socket = socket(AF_INET, SOCK_STREAM, 0); //socket initialization for ipv4 with TCP
    client->server_addr.sin_family = AF_INET;
    client->server_addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &client->server_addr.sin_addr); //to convert ip string to binary form
    SSL_library_init(); //initializes the SSL library, must be called before any other SSL functions
    client->ssl = SSL_new(SSL_CTX_new(TLS_client_method())); //create new SSL context for the client using TLS method
    SSL_CTX_set_min_proto_version(SSL_CTX_new(TLS_client_method()), TLS1_2_VERSION); //set minimum TLS version to 1.2 for better security
    SSL_set_fd(client->ssl, client->socket); //associate the SSL context with the client socket
    if(SSL_connect(client->ssl) <= 0){ //perform SSL handshake with the server, establishing a secure connection 
        ERR_print_errors_fp(stderr); 
        close(client->socket);
        exit(EXIT_FAILURE);
    }
    connect(client->socket, (struct sockaddr*) &client->server_addr, sizeof(client->server_addr));
    SSL_new(client->tls_ctx); //create new SSL context for the client using TLS method
    SSL_set_fd(client->ssl, client->socket); //associate the SSL context with the client socket
    if(SSL_connect(client->ssl) <= 0){
        ERR_print_errors_fp(stderr); 
        close(client->socket);
        exit(EXIT_FAILURE);
    }
}

void send_message_to_server(client_connection_t *client, const message_t *message){
    SSL_write(client->ssl, message, sizeof(*message)); //send message securely over SSL connection
}

int receive_message_from_server(client_connection_t *client, message_t *message){
    return SSL_read(client->ssl, message, sizeof(*message)); //receive message securely over SSL connection
}

void run_client(client_connection_t *client){
    char buffer[BUFFER_SIZE];
    message_t message;
    message_t response;

    // One-time login handshake before entering the chat loop.
    memset(&message, 0, sizeof(message));
    message.type = LOGIN;
    printf("Password: ");
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        return;
    }
    buffer[strcspn(buffer, "\n")] = '\0';
    snprintf(message.content, sizeof(message.content), "%s", buffer);
    send_message_to_server(client, &message);

    if (receive_message_from_server(client, &response) <= 0) {
        printf("Failed to receive login response from server.\n");
        return;
    }

    printf("Login response: %s\n", response.content);
    if (strstr(response.content, "Authentication failed") != NULL) {
        return;
    }

    while(1){
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            break;
        }
        buffer[strcspn(buffer, "\n")] = '\0';

        memset(&message, 0, sizeof(message));
        message.type = PRIVATE_MESSAGE;
        snprintf(message.content, sizeof(message.content), "%s", buffer);
        send_message_to_server(client, &message);

        if(receive_message_from_server(client, &response) > 0){
            printf("Server response: %s\n", response.content);
        } else{
            printf("Failed to receive response from server.\n");
            break;
        }
    }
}

void send_to_room(client_connection_t *client, const char* room_name, const char* message){
    messag_t msg; 
    msg.type = ROOM_MESSAGE;
    snprintf(msg.receiver_name, sizeof(msg.receiver_name), "%s", room_name);
    snprintf(msg.content, sizeof(msg.content), "%s", message);
    send_message_to_server(client, &msg);
}

void leave_room(client_connection_t *client, const char* room_name){
    message_t msg; 
    msg.type = LEAVE_ROOM; 
    snprintf(msg.receiver_name, sizeof(msg.receiver_name), "%s", room_name);
    send_message_to_server(client, &msg);
}

void join_room(client_connection_t *client, const char* room_name){
    message_t msg; 
    msg.type = JOIN_ROOM; 
    snprintf(msg.receiver_name, sizeof(msg.receiver_name), "%s", room_name);
    send_message_to_server(client, &msg);
}