#include "server.h"

#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#define AUTH_NONCE_BYTES 16
#define AUTH_NONCE_HEX_LEN (AUTH_NONCE_BYTES * 2)
#define AUTH_PROOF_HEX_LEN 64
#define AUTH_MAX_ATTEMPTS 5


static const char *get_server_password(void){
    const char *password = getenv("CHAT_SERVER_PASSWORD");
    if (password != NULL && password[0] != '\0') {
        return password;
    }
    return "dev-password-change-me";
}

static int compute_proof_hex(const char *nonce_hex, const char *password, char *proof_hex, size_t proof_hex_size){
    char material[256];
    int written = snprintf(material, sizeof(material), "%s:%s", nonce_hex, password);
    if (written < 0 || written >= (int)sizeof(material)) {
        return -1;
    }
    return sha256_hex_string(material, proof_hex, proof_hex_size);
}

static void bytes_to_hex(const unsigned char *bytes, size_t bytes_len, char *hex_out, size_t hex_out_size){
    static const char lut[] = "0123456789abcdef";
    size_t required = (bytes_len * 2) + 1;

    if (hex_out_size < required) {
        if (hex_out_size > 0) {
            hex_out[0] = '\0';
        }
        return;
    }

    for (size_t i = 0; i < bytes_len; ++i) {
        hex_out[i * 2] = lut[(bytes[i] >> 4) & 0x0F];
        hex_out[(i * 2) + 1] = lut[bytes[i] & 0x0F];
    }
    hex_out[bytes_len * 2] = '\0';
}

static int generate_nonce_hex(char *nonce_hex, size_t nonce_hex_size){
    unsigned char nonce_bytes[AUTH_NONCE_BYTES];

    if (nonce_hex_size < (AUTH_NONCE_HEX_LEN + 1)) {
        return -1;
    }

    for (size_t i = 0; i < AUTH_NONCE_BYTES; ++i) {
        unsigned int value = 0;
        if (rand_s(&value) != 0) {
            return -1;
        }
        nonce_bytes[i] = (unsigned char)(value & 0xFF);
    }

    bytes_to_hex(nonce_bytes, sizeof(nonce_bytes), nonce_hex, nonce_hex_size);
    return 0;
}

static int sha256_hex_string(const char *input, char *output_hex, size_t output_hex_size){
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    PUCHAR hash_object = NULL;
    PUCHAR hash_bytes = NULL;
    DWORD hash_object_size = 0;
    DWORD hash_size = 0;
    DWORD data_size = 0;
    NTSTATUS status;
    int result = -1;

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status != 0) {
        goto cleanup;
    }

    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hash_object_size, sizeof(hash_object_size), &data_size, 0);
    if (status != 0) {
        goto cleanup;
    }

    status = BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_size, sizeof(hash_size), &data_size, 0);
    if (status != 0) {
        goto cleanup;
    }

    hash_object = (PUCHAR)malloc(hash_object_size);
    hash_bytes = (PUCHAR)malloc(hash_size);
    if (hash_object == NULL || hash_bytes == NULL) {
        goto cleanup;
    }

    status = BCryptCreateHash(algorithm, &hash, hash_object, hash_object_size, NULL, 0, 0);
    if (status != 0) {
        goto cleanup;
    }

    status = BCryptHashData(hash, (PUCHAR)input, (ULONG)strlen(input), 0);
    if (status != 0) {
        goto cleanup;
    }

    status = BCryptFinishHash(hash, hash_bytes, hash_size, 0);
    if (status != 0) {
        goto cleanup;
    }

    bytes_to_hex(hash_bytes, hash_size, output_hex, output_hex_size);
    result = 0;

cleanup:
    if (hash != NULL) {
        BCryptDestroyHash(hash);
    }
    if (algorithm != NULL) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    if (hash_object != NULL) {
        free(hash_object);
    }
    if (hash_bytes != NULL) {
        free(hash_bytes);
    }
    return result;
}

static int constant_time_equals(const char *a, const char *b, size_t n){
    unsigned char diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0;
}

serverstate_t state;

typedef struct client_thread_ctx_t {
    server_t *server;
    client_t *client;
} client_thread_ctx_t;

static void *client_thread_start(void *arg){
    client_thread_ctx_t *ctx = (client_thread_ctx_t *)arg;
    if (ctx != NULL) {
        handle_client(*ctx->server, *ctx->client);
        free(ctx);
    }
    return NULL;
}

static SSL_CTX* create_server_ctx(void){
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL){
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    SSL_library_init();  //Initialize OpenSSL
    SSL_load_error_strings(); //load error strings for better error reporting
    OpenSSL_add_ssl_algorithms(); //load all algorithms, including ciphers and digests

    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) == 0) //set minimum TLS version to 1.2 for better security
    {
        ERR_print_errors_fp(stderr); //print any errors that occured during context setup
        SSL_CTX_free(ctx); //free the context to avoid memory leaks
        return NULL;
    }

    if(SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0){ //load server certificate, must be in PEM format
        ERR_print_errors_fp(stderr); //print erroers if certificate loading fails
        SSL_CTX_free(ctx); //free context to avoid memory leaks
        return NULL; //return NULL on failure
    }

    if(SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0){
        //load server private key, must be in PEM format
        ERR_print_errors_fp(stderr); //print errors if occured
        SSL_CTX_free(ctx); //free context to avoid memory leaks
        return NULL; //return NULL on failure
    }
    if(!SSL_CTX_check_private_key(ctx)){ //check if private key matches the certificate public key
        fprintf(stderr, "Private key does not match the certificate public key\n"); 
        SSL_CTX_free(ctx); //free context to avoid memory leaks
        return NULL;
    }

    /*Abbiamo impostato la versione minima accettabile nella comunicazione alla 1.2, 
    abbiamo poi specificato il file contenente il certificato, specificato il file della chiave 
    privata, e poi verifichiamo la compatibilità tra chiave privata e pubblica*/

    return ctx; //return the initialized SSL context
}

void init_server(serverstate_t *state){
    state->server.server_socket = socket(AF_INET, SOCK_STREAM, 0);
    state->server.server_addr.sin_family = AF_INET;
    state->server.server_addr.sin_addr.s_addr = INADDR_ANY;
    state->server.server_addr.sin_port = htons(PORT);
    bind(state->server.server_socket, (struct sockaddr*)&state->server.server_addr, sizeof(state->server.server_addr));
    listen(state->server.server_socket, 10);
    state->server.client_count = 0;
    state->room_count = 0;
    state->server.ssl_ctx = create_server_ctx();
}

void start_server(server_t server){
    while(1){
        int client_socket = accept(server.server_socket, NULL, NULL);
        SSL *ssl;
        int client_index;

        if(client_socket < 0){
            perror("Accept failed");
            continue;
        }

        ssl = SSL_new(server.ssl_ctx);
        if (ssl == NULL) {
            close(client_socket);
            continue;
        }

        SSL_set_fd(ssl, client_socket);
        if (SSL_accept(ssl) <= 0){
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        if (state.server.client_count >= MAX_CLIENTS) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        client_t new_client;
        memset(&new_client, 0, sizeof(new_client));
        new_client.socket = client_socket;
        new_client.state = CONNECTED;
        new_client.ssl = ssl;
        client_index = state.server.client_count;
        state.server.clients[state.server.client_count++] = new_client;

        pthread_t thread_id;
        client_thread_ctx_t *ctx = (client_thread_ctx_t *)malloc(sizeof(client_thread_ctx_t));
        if (ctx == NULL) {
            cleanup_client(&state.server.clients[client_index]);
            continue;
        }

        ctx->server = &state.server;
        ctx->client = &state.server.clients[client_index];
        pthread_create(&thread_id, NULL, client_thread_start, ctx);
    }
}

void handle_client(server_t server, client_t client){
    while(1){
        message_t message;
        int bytes_received = receive_message(client, &message);
        if(bytes_received <= 0){
            cleanup_client(&client);
            return;
        }
        // Process a validated packet.
        switch(message.type){
            case LOGIN:
                // Generate and send a fresh nonce challenge for this login attempt.
                message_t challenge_msg;
                memset(&challenge_msg, 0, sizeof(challenge_msg));
                challenge_msg.type = AUTH_CHALLENGE;
                if (generate_nonce_hex(client.auth_nonce, sizeof(client.auth_nonce)) != 0) {
                    challenge_msg.type = AUTH_RESULT;
                    challenge_msg.flags = 0;
                    snprintf(challenge_msg.content, sizeof(challenge_msg.content), "Auth challenge generation failed");
                    send_message(client, challenge_msg);
                    break;
                }
                client.auth_challenge_sent = 1;
                snprintf(challenge_msg.content, sizeof(challenge_msg.content), "%s", client.auth_nonce);
                send_message(client, challenge_msg);
                break;
            case LOGOUT: 
                cleanup_client(&client);
                return;
            case PRIVATE_MESSAGE: 
                acknowledge_message(client, message);
                send_private_message(server, client, message);
                break;
            case ROOM_MESSAGE:
                broadcast_message(server, message);
                break;
            case JOIN_ROOM:
                join_room(&client, message.receiver_name);
                break;
            case LEAVE_ROOM: 
                leave_room(&client, message.receiver_name);
                break;
            case PING: 
                send_message(client, message); 
                break;
            case AUTH_RESPONSE: 
                authenticate_client(&client, message);
                break;
            case BAN_USER:
                ban_user_from_room(&client, message.receiver_name, message.content);
                break;
            default: 
                printf("Unknown message type from client %s\n", client.name);
                break;
        }
    }
}

/*
    1 => LOGIN arrivato nel loop, viene generato un nonce casuale, viene salvato nella struttura del client
    e viene impostata su 1 l'auth_challenge_sent, poi viene inviato il nonce al client come sfida. 
    2 => Il client risponde con un AUTH RESPONSE che contiene la prova computata usando il nonce e la password. 
    3 => prepara la stringa attesa e invia un messagio di tipo AUTH_RESULT con flag 1 se laprova è corretta
    4 => se la prova è errata, incrementa il contatore dei tentativi falliti, resetta lo stato di sfida e invia un messaggio di AUTH_RESULT con flag 0. Se i tentativi falliti superano il limite, disconnette il client.
    5 => se il client prova a rispondere senza una sfida attiva, invia un messaggio di AUTH_RESULT con flag 0 e un messaggio di errore.
*/

void authenticate_client(client_t *client, message_t message){
    char expected[AUTH_PROOF_HEX_LEN + 1]; //expected hex string
    message_t response;

    memset(expected, 0, sizeof(expected));
    memset(&response, 0, sizeof(response));
    response.type = AUTH_RESULT; //setting respone type to auth result

    if (!client->auth_challenge_sent) { //client is trying to respond without a challenge
        response.flags = 0;
        snprintf(response.content, sizeof(response.content), "No auth challenge pending");
        send_message(*client, response);
        return;
    }

    if (strlen(message.content) != AUTH_PROOF_HEX_LEN) { //invalid length of proof
        client->failed_attempts++;
        response.flags = 0;
        snprintf(response.content, sizeof(response.content), "Invalid auth proof format");
        send_message(*client, response);
        return;
    }

    // compute expected proof and comapre in constant time
    if (compute_proof_hex(client->auth_nonce, get_server_password(), expected, sizeof(expected)) != 0) {
        response.flags = 0;
        snprintf(response.content, sizeof(response.content), "Server auth verification error");
        send_message(*client, response);
        return;
    }

    // clear the challenge state 
    if (constant_time_equals(expected, message.content, AUTH_PROOF_HEX_LEN)) {
        client->state = AUTHENTICATED;
        client->auth_challenge_sent = 0;
        client->failed_attempts = 0;
        memset(client->auth_nonce, 0, sizeof(client->auth_nonce));

        response.flags = 1;
        snprintf(response.content, sizeof(response.content), "Welcome %s!", client->name[0] ? client->name : "USER");
        send_message(*client, response);
        return;
    }

    client->failed_attempts++;
    client->state = CONNECTED;
    client->auth_challenge_sent = 0;
    memset(client->auth_nonce, 0, sizeof(client->auth_nonce));

    response.flags = 0;
    if (client->failed_attempts >= AUTH_MAX_ATTEMPTS) {
        snprintf(response.content, sizeof(response.content), "Authentication failed: too many attempts");
        send_message(*client, response);
        cleanup_client(client);
        return;
    }

    snprintf(response.content, sizeof(response.content), "Authentication failed!");
    send_message(*client, response);
}

void send_private_message(server_t server, client_t sender, message_t message){
    for(int i=0; i<server.client_count; i++){
        if(strncmp(server.clients[i].name, message.receiver_name, 50) == 0){
            send_message(server.clients[i], message); 
            store_message(server, NULL, message); //store private message with no room association
            break;
        }
    }
}

void broadcast_message(server_t server, message_t message){
    for(int i=0; i<server.client_count; i++){
        if(server.clients[i].state == IN_ROOM){
            send_message(server.clients[i], message);
        }
    }
}

void send_message(client_t client, message_t message){
    //send(client.scocket, &message, sizeof(message), 0);
    SSL_write(client.ssl, &message, sizeof(message)); //send message securely over SSL connection
}

int receive_message(client_t client, message_t *message){
    int bytes_received = SSL_read(client.ssl, message, sizeof(*message)); //receive message securely over SSL connection
    if (bytes_received <= 0) {
        return bytes_received;
    }

    if (bytes_received < (int)sizeof(message_t)) {
        // Partial payload: mark as invalid and let caller decide how to handle it.
        memset(message, 0, sizeof(*message));
        return -1;
    }

    return bytes_received;
}

static room_t *find_room_by_name(const char *room_name){
    for (int i = 0; i < state.room_count; ++i) {
        if (strncmp(state.rooms[i].room_name, room_name, sizeof(state.rooms[i].room_name)) == 0) {
            return &state.rooms[i];
        }
    }
    return NULL;
}

static int find_member_index(const room_t *room, const client_t *client){
    if (room == NULL || client == NULL) {
        return -1;
    }

    for (int i = 0; i < room->member_count; ++i) {
        if (room->members[i].client != NULL && room->members[i].client->socket == client->socket) {
            return i;
        }
    }
    return -1;
}

void join_room(client_t *client, char* room_name){
    room_t *room;

    if(client == NULL){
        return;
    }

    if(client->state != AUTHENTICATED){
        message_t msg; 
        memset(&msg, 0, sizeof(msg));
        msg.type = JOIN_ROOM;
        snprintf(msg.content, BUFFER_SIZE, "You must be authenticated to join a room!");
        send_message(*client, msg);
        return;
    }

    if(room_name == NULL || room_name[0] == '\0'){
        message_t msg;
        memset(&msg, 0, sizeof(msg));
        msg.type = JOIN_ROOM;
        snprintf(msg.content, BUFFER_SIZE, "Room name is required");
        send_message(*client, msg);
        return;
    }

    room = find_room_by_name(room_name);
    if (room == NULL && state.room_count >= MAX_ROOMS){
        message_t msg; 
        memset(&msg, 0, sizeof(msg));
        msg.type = JOIN_ROOM;
        snprintf(msg.content, BUFFER_SIZE, "Room limit reached!");
        send_message(*client, msg);
        return;
    }

    if (room == NULL) {
        room = &state.rooms[state.room_count++];
        memset(room, 0, sizeof(*room));
        strncpy(room->room_name, room_name, sizeof(room->room_name) - 1);
    }

    if (find_member_index(room, client) >= 0) {
        return;
    }

    if (room->member_count >= MAX_CLIENTS) {
        message_t msg;
        memset(&msg, 0, sizeof(msg));
        msg.type = JOIN_ROOM;
        snprintf(msg.content, BUFFER_SIZE, "Room is full");
        send_message(*client, msg);
        return;
    }

    room->members[room->member_count].client = client;
    room->members[room->member_count].role = (room->member_count == 0) ? OWNER : MEMBER;
    room->member_count++;

    client->state = IN_ROOM;
    notify_room_join(client, room_name);
}

void leave_room(client_t *client, char* room_name){
    room_t *room = find_room_by_name(room_name);
    int member_index;
    int was_owner = 0;

    if (client == NULL) {
        return;
    }

    if (room == NULL) {
        return;
    }

    member_index = find_member_index(room, client);
    if (member_index < 0) {
        return;
    }

    was_owner = (room->members[member_index].role == OWNER);

    for (int i = member_index; i < room->member_count - 1; ++i) {
        room->members[i] = room->members[i + 1];
    }
    room->member_count--;
    if (room->member_count >= 0) {
        room->members[room->member_count].client = NULL;
        room->members[room->member_count].role = MEMBER;
    }

    if (was_owner && room->member_count > 0) {
        room->members[0].role = OWNER;
    }

    if (room->member_count == 0) {
        for (int i = 0; i < state.room_count; ++i) {
            if (&state.rooms[i] == room) {
                for (int j = i; j < state.room_count - 1; ++j) {
                    state.rooms[j] = state.rooms[j + 1];
                }
                state.room_count--;
                break;
            }
        }
    }

    client->state = AUTHENTICATED;
    notify_room_leave(client, room_name);
}

void cleanup_client(client_t *client){
    if (client == NULL) {
        return;
    }

    for (int i = 0; i < state.room_count; i++) {
        room_t *room = &state.rooms[i];
        int member_index = find_member_index(room, client);
        if (member_index >= 0) {
            for (int j = member_index; j < room->member_count - 1; ++j) {
                room->members[j] = room->members[j + 1];
            }
            room->member_count--;
        }
    }

    for(int i = 0; i < state.server.client_count; i++){
        if(state.server.clients[i].socket == client->socket){
            state.server.clients[i] = state.server.clients[--state.server.client_count];
            break;
        }
    }

    if (client->ssl != NULL) {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
        client->ssl = NULL;
    }

    if (client->socket >= 0) {
        close(client->socket);
        client->socket = -1;
    }

    client->state = DISCONNECTED;
    client->auth_challenge_sent = 0;
    memset(client->auth_nonce, 0, sizeof(client->auth_nonce));
}

/*
void cleanup_client_legacy(client_t client){
    for(int i=0; i<state.room_count; i++){
        if(state.rooms[i].clients[client.socket] != NULL){
            state.rooms[i].clients[client.socket] = NULL;
        }
    }
    for(int i=0; i<state.server.client_count; i++){
        if(state.server.clients[i].socket == client.socket){
            state.server.clients[i] = state.server.clients[--state.server.client_count]; 
            break;
        }
    }
}
*/


int main(){
    init_server(&state);
    start_server(state.server);
    return 0;
}

/*Gestione della sicurezza con openSSL: 
1 => creazione dei contesti SSL all'interno delle strutture che rappresentano i client e il server
2 => SSL per il contesto del client e ssl_ctx per il contesto del server
3 => invece che usare send e recv usiamo le varianti che applicano l'encryption
4 => in caso di errore nel setup del contesto stampiamo gli errori con ERR_print_errors_fp 
5 => per il cleanup del client, chiudiamo la connessione SSL e liberiamo le risorse associate prima di chiudere il socket 
6 => i metodi principali usati sono 
    - SSL_new() per creare un nuovo contesto SSL per ogni client
    - SSL_set_fd() per associare il contesto SSL al socket del client
    - SSL_connect() per eseguire l'handshake SSL con il client
    - SSL_write() e SSL_read() per inviare e ricevere dati in modo sicuro
    - ssl_shutdown() e ssl_free() per pulire le risorse SSL quando un client si disconnette

7 =>create_server_ctx() è una funzione helper che inizializza un contesto SSL per il server
    - SSL_CTX_new(TLS_server_method()) crea un nuovo contesto SSL per il server utilizzando il metodo TLS
    - SSL_CTX_set_min_proto_version() imposta la versione minima di TLS accettata (1.2 in questo caso)
    - SSL_CTX_use_certificate_file() carica il certificato del server da un file PEM
    - SSL_CTX_use_PrivateKey_file() carica la chiave privata del server da un file PEM
    . SSL_CTX_ckeck_private_key() verifica che la chiave privata corrisponda al certificato caricato 

openssl list -cipher-algorithms per mostrare gli algoritmi disponibili di cifratura
openssl list -digest-algorithms per mostrare gli algoritmi di digest disponibili
openssl genrsa -aes256 -out server_key.pem 2048 per generare una chiave privata con cifratura AES-256
openssl genrsa -out chiave.pem 2048 per generare una chiave privata senza cifratura
openssl req -new -key server_key.pem -out server_csr.pem per generare una richiesta di firma del certificato (CSR) usando la chiave privata
open req -x509 -nodes -days 365 
    -newkey rsa:2048 -keyout server_key.pem 
    -out certificato.crt
per generare un certificato autofirmato valido per 365 giorni usando una nuova chiave RSA a 2048 bit e salvando la chiave privata in server_key.pem e il certificato in certificato.crt
*/
void check_command(message_t message, command_check *check, char *arg){
    if (message.type != ROOM_MESSAGE || message.content[0] != '/') {
        *check = UNKNOWN_COMMAND;
        return;
    }

    arg[0] = '\0';
    char *space = strchr(message.content, ' ');
    if (space != NULL) {
        *space = '\0';
        strncpy(arg, space + 1, BUFFER_SIZE - 1);
        arg[BUFFER_SIZE - 1] = '\0';
    }

    if (strcmp(message.content, "/join") == 0 ||
        strcmp(message.content, "/leave") == 0 ||
        strcmp(message.content, "/rooms") == 0 ||
        strcmp(message.content, "/users") == 0 ||
        strcmp(message.content, "/help") == 0 ||
        strcmp(message.content, "/show") == 0) {
        *check = VALID_COMMAND;
    } else {
        *check = INVALID_COMMAND;
    }
}

static void send_message_to_client(server_t server, const char *client_name, message_t message){
    for (int i = 0; i < server.client_count; ++i) {
        if (strcmp(server.clients[i].name, client_name) == 0) {
            send_message(server.clients[i], message);
            return;
        }
    }
}

void send_help_message(server_t server, char* client_name){
    message_t message; 
    memset(&message, 0, sizeof(message));
    message.type = ROOM_MESSAGE;
    snprintf(message.content, BUFFER_SIZE, "Available commands:\n/join [room_name] - Join or create a room\n/leave [room_name] - Leave a room\n/rooms - List available rooms\n/users [room_name] - List users in a room\n/help - Show this help message");
    send_message_to_client(server, client_name, message);
}

void show_user_rooms(server_t server, char* client_name, char* arg){
    (void)arg;
    message_t response; 
    response.type = ROOM_MESSAGE;
    char rooms_list[BUFFER_SIZE];

    memset(rooms_list, 0, sizeof(rooms_list));
    for (int i = 0; i < state.room_count; i++) {
        for (int j = 0; j < state.rooms[i].member_count; j++) {
            if (state.rooms[i].members[j].client != NULL &&
                strcmp(state.rooms[i].members[j].client->name, client_name) == 0) {
                strncat(rooms_list, state.rooms[i].room_name, sizeof(rooms_list) - strlen(rooms_list) - 1);
                strncat(rooms_list, "\n", sizeof(rooms_list) - strlen(rooms_list) - 1);
            }
        }
    }

    if (rooms_list[0] == '\0') {
        snprintf(response.content, BUFFER_SIZE, "You are not in any room");
    } else {
        snprintf(response.content, BUFFER_SIZE, "Rooms you are in:\n%s", rooms_list);
    }

    send_message_to_client(server, client_name, response);
}

void show_room_users(server_t server, char* client_name, char * arg){
    message_t response; 
    response.type = ROOM_MESSAGE; 
    char user_list[BUFFER_SIZE];

    memset(user_list, 0, sizeof(user_list));
    for (int i = 0; i < state.room_count; i++) {
        if (strcmp(state.rooms[i].room_name, arg) == 0) {
            for (int j = 0; j < state.rooms[i].member_count; j++) {
                if (state.rooms[i].members[j].client == NULL) {
                    continue;
                }
                strncat(user_list, state.rooms[i].members[j].client->name, sizeof(user_list) - strlen(user_list) - 1);
                strncat(user_list, " (", sizeof(user_list) - strlen(user_list) - 1);
                if (state.rooms[i].members[j].role == OWNER) {
                    strncat(user_list, "owner", sizeof(user_list) - strlen(user_list) - 1);
                } else if (state.rooms[i].members[j].role == MODERATOR) {
                    strncat(user_list, "moderator", sizeof(user_list) - strlen(user_list) - 1);
                } else {
                    strncat(user_list, "member", sizeof(user_list) - strlen(user_list) - 1);
                }
                strncat(user_list, ")\n", sizeof(user_list) - strlen(user_list) - 1);
            }
            break;
        }
    }

    if (user_list[0] == '\0') {
        snprintf(response.content, BUFFER_SIZE, "Room %s not found or empty", arg);
    } else {
        snprintf(response.content, BUFFER_SIZE, "Users in room %s:\n%s", arg, user_list);
    }

    send_message_to_client(server, client_name, response);
}

void notify_room_join(client_t *client, char* room_name){
    message_t notification; 

    if (client == NULL) {
        return;
    }

    memset(&notification, 0, sizeof(notification));
    notification.type = ROOM_MESSAGE;
    snprintf(notification.content, BUFFER_SIZE, "%s has joined the room!", client->name);
    for(int i=0; i<state.room_count; i++){
        if(strcmp(state.rooms[i].room_name, room_name) == 0){
            for(int j=0; j<state.rooms[i].member_count; j++){
                if(state.rooms[i].members[j].client != NULL && state.rooms[i].members[j].client->socket != client->socket){
                    send_message(*state.rooms[i].members[j].client, notification);
                }
            }
            break;
        }
    }
}

void notify_room_leave(client_t *client, char* room_name){
    message_t notification; 

    if (client == NULL) {
        return;
    }

    memset(&notification, 0, sizeof(notification));
    notification.type = ROOM_MESSAGE;
    snprintf(notification.content, BUFFER_SIZE, "%s has left the room!", client->name);
    for(int i=0; i<state.room_count; i++){
        if(strcmp(state.rooms[i].room_name, room_name) == 0){
            for(int j=0; j<state.rooms[i].member_count; j++){
                if(state.rooms[i].members[j].client != NULL && state.rooms[i].members[j].client->socket != client->socket){
                    send_message(*state.rooms[i].members[j].client, notification);
                }
            }
            break;
        }
    }
}

void store_message(server_t server, char* room_name, message_t message){
    (void)server;
    (void)room_name;
    FILE *F = fopen("message_history.txt", "a");
    if(F == NULL){
        printf("Error opening message history file for writing\n");
        return;
    }
    fprintf(F, "|%s|%s|%s|%d|%d|%d|\n", message.sender_name, message.receiver_name, message.content, message.type, message.length, message.flags);
    fclose(F);
}

void show_messages(server_t server, char* client_name, char* arg){
    FILE *F = fopen("message_history.txt", "r");
    message_t response;
    if(F == NULL){
        printf("Error opening message history file for reading\n");
        return;
    }

    memset(&response, 0, sizeof(response));
    response.type = ROOM_MESSAGE;

    char line[BUFFER_SIZE]; 
    char messages[BUFFER_SIZE];
    memset(messages, 0, sizeof(messages));
    while(fgets(line, sizeof(line), F)){
        char sender[50], receiver[50], content[BUFFER_SIZE];
        int type, length, flags;
        if (sscanf(line, "|%49[^|]|%49[^|]|%4095[^|]|%d|%d|%d|", sender, receiver, content, &type, &length, &flags) != 6) {
            continue;
        }
        if((strcmp(sender, client_name) == 0 || strcmp(receiver, client_name) == 0) &&
            (arg[0] == '\0' || strcmp(arg, "all") == 0 || strcmp(arg, sender) == 0 || strcmp(arg, receiver) == 0)){
            strncat(messages, line, sizeof(messages) - strlen(messages) - 1);
        }
    }

    fclose(F);

    if (messages[0] == '\0') {
        snprintf(response.content, BUFFER_SIZE, "No messages found");
    } else {
        snprintf(response.content, BUFFER_SIZE, "%s", messages);
    }
    send_message_to_client(server, client_name, response);
}

void acknowledge_message(client_t client, message_t message){
    message_t ack; 
    ack.type = ACK;
    snprintf(ack.content, BUFFER_SIZE, "The server has accepted the message: %s", message.content);
    send_message(client, ack);
}

void ban_user_from_room(client_t *client, char* room_name, char* target_name){
    room_t *room = find_room_by_name(room_name);
    if (client == NULL || room == NULL) {
        return;
    }
    int client_index = find_member_index(room, client);
    if (client_index < 0 || room->members[client_index].role != OWNER && room->members[client_index].role != MODERATOR) {
        message_t msg;
        memset(&msg, 0, sizeof(msg));
        msg.type = ROOM_MESSAGE;
        snprintf(msg.content, BUFFER_SIZE, "Only the room owner or moderator can ban users");
        send_message(*client, msg);
        return;
    }
    for(int i = 0; i<room->member_count; i++){
        if(room->members[i].client != NULL && strcmp(room->members[i].client->name, target_name) == 0){
            message_t notification;
            memset(&notification, 0, sizeof(notification));
            notification.type = ROOM_MESSAGE;
            snprintf(notification.content, BUFFER_SIZE, "You have been banned from room %s by the owner or a moderator", room_name);
            send_message(*room->members[i].client, notification);
            if(room->banned_count < MAX_CLIENTS){
                room->banned_clients[room->banned_count++] = room->members[i].client;
            } else {
                printf("Warning: banned clients limit reached for room %s, cannot track more banned users\n", room_name);
            }
            leave_room(room->members[i].client, room_name);
            break;
        }
    }
}

void unban_user_from_room(client_t *client, char* room_name, char* target_name){
    room_t *room = find_room_by_name(room_name);
    if (client == NULL || room == NULL) {
        return;
    }
    int client_index = find_member_index(room, client);
    if(client_index < 0 || room->members[client_index].role != OWNER && room->members[client_index].role != MODERATOR) {
        message_t msg;
        memset(&msg, 0, sizeof(msg));
        msg.type = ROOM_MESSAGE;
        snprintf(msg.content, BUFFER_SIZE, "Only the room owner or moderator can unban users");
        send_message(*client, msg);
        return;
    }
    for(int i = 0; i<room->banned_count; i++){
        if(room->banned_clients[i] != NULL && strcmp(room->banned_clients[i]->name, target_name) == 0){
            for(int j = i; j<room->banned_count - 1; j++){
                room->banned_clients[j] = room->banned_clients[j + 1];
            }
            room->banned_clients[--room->banned_count] = NULL;
            message_t notification;
            memset(&notification, 0, sizeof(notification));
            notification.type = ROOM_MESSAGE;
            snprintf(notification.content, BUFFER_SIZE, "You have been unbanned from room %s by the owner or a moderator", room_name);
            send_message_to_client(*client, target_name, notification);
            break;
        }
    }
}