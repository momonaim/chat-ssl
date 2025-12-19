// server_ssl.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sqlite3.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8888
#define MAX_CLIENTS 100
#define BUFFER_SIZE 4096

typedef struct
{
    int socket;
    SSL *ssl;
    char username[50];
    char ip_address[INET_ADDRSTRLEN];
    int port;
    int is_authenticated;
} ClientInfo;

typedef struct
{
    int type; // 0: private, 1: group, 2: server
    char sender[50];
    char receiver[50];
    char group[50];
    char message[BUFFER_SIZE];
} ChatMessage;

ClientInfo *clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
SSL_CTX *ssl_context;
sqlite3 *db;

// Initialisation du contexte SSL
SSL_CTX *init_ssl_context()
{
    SSL_CTX *ctx;
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

// Initialisation de la base de données
int init_database()
{
    int rc = sqlite3_open("chat_app.db", &db);
    if (rc)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    // Exécution du script SQL
    FILE *sql_file = fopen("users.sql", "r");
    if (sql_file)
    {
        char sql_buffer[4096];
        char *err_msg = 0;

        while (fgets(sql_buffer, sizeof(sql_buffer), sql_file))
        {
            rc = sqlite3_exec(db, sql_buffer, 0, 0, &err_msg);
            if (rc != SQLITE_OK)
            {
                fprintf(stderr, "SQL error: %s\n", err_msg);
                sqlite3_free(err_msg);
            }
        }
        fclose(sql_file);
    }

    return 0;
}

// Authentification de l'utilisateur
int authenticate_user(char *username, char *password)
{
    char sql[512];
    sqlite3_stmt *stmt;

    sprintf(sql, "SELECT id, password_hash FROM users WHERE username = ?");

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK)
    {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) == SQLITE_ROW)
        {
            // Vérifier le mot de passe (simplifié - utiliser bcrypt en production)
            const char *stored_hash = (const char *)sqlite3_column_text(stmt, 1);
            // Ici, vous devriez utiliser une fonction de hachage sécurisée
            if (strcmp(password, stored_hash) == 0)
            {
                int user_id = sqlite3_column_int(stmt, 0);
                sqlite3_finalize(stmt);
                return user_id;
            }
        }
        else
        {
            // Créer un nouvel utilisateur
            sqlite3_finalize(stmt);
            sprintf(sql, "INSERT INTO users (username, password_hash) VALUES (?, ?)");
            if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK)
            {
                sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC); // Hacher en production
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                return sqlite3_last_insert_rowid(db);
            }
        }
    }

    return -1;
}

// Envoi de message à un client
void send_to_client(SSL *ssl, char *message)
{
    SSL_write(ssl, message, strlen(message));
}

// Diffusion à tous les clients
void broadcast_message(char *message, int exclude_client)
{
    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (clients[i] && clients[i]->is_authenticated && i != exclude_client)
        {
            send_to_client(clients[i]->ssl, message);
        }
    }

    pthread_mutex_unlock(&clients_mutex);
}

// Gestion des commandes
void handle_command(ClientInfo *client, char *command)
{
    char buffer[BUFFER_SIZE];
    char *token = strtok(command, " ");

    if (strcmp(token, "/join") == 0)
    {
        token = strtok(NULL, " ");
        sprintf(buffer, "SERVER: Vous avez rejoint le groupe %s\n", token);
        send_to_client(client->ssl, buffer);
    }
    else if (strcmp(token, "/private") == 0)
    {
        char *target_user = strtok(NULL, " ");
        char *message = strtok(NULL, "\n");

        sprintf(buffer, "PRIVATE from %s: %s\n", client->username, message);

        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (clients[i] && strcmp(clients[i]->username, target_user) == 0)
            {
                send_to_client(clients[i]->ssl, buffer);
                break;
            }
        }
        pthread_mutex_unlock(&clients_mutex);
    }
    else if (strcmp(token, "/users") == 0)
    {
        sprintf(buffer, "=== Utilisateurs connectés ===\n");
        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (clients[i] && clients[i]->is_authenticated)
            {
                sprintf(buffer + strlen(buffer), "- %s (%s:%d)\n",
                        clients[i]->username, clients[i]->ip_address, clients[i]->port);
            }
        }
        pthread_mutex_unlock(&clients_mutex);
        send_to_client(client->ssl, buffer);
    }
    else if (strcmp(token, "/help") == 0)
    {
        sprintf(buffer, "=== Commandes disponibles ===\n"
                        "/join [groupe] - Rejoindre un groupe\n"
                        "/private [user] [message] - Message privé\n"
                        "/users - Liste des utilisateurs\n"
                        "/help - Afficher l'aide\n"
                        "/quit - Quitter\n");
        send_to_client(client->ssl, buffer);
    }
}

// Thread de traitement client
void *handle_client(void *arg)
{
    ClientInfo *client = (ClientInfo *)arg;
    char buffer[BUFFER_SIZE];
    int bytes_received;

    // Authentification
    sprintf(buffer, "Entrez votre nom d'utilisateur: ");
    send_to_client(client->ssl, buffer);

    bytes_received = SSL_read(client->ssl, buffer, BUFFER_SIZE);
    buffer[bytes_received] = '\0';
    buffer[strcspn(buffer, "\n")] = 0;
    strcpy(client->username, buffer);

    sprintf(buffer, "Entrez votre mot de passe: ");
    send_to_client(client->ssl, buffer);

    bytes_received = SSL_read(client->ssl, buffer, BUFFER_SIZE);
    buffer[bytes_received] = '\0';
    buffer[strcspn(buffer, "\n")] = 0;

    int user_id = authenticate_user(client->username, buffer);
    if (user_id > 0)
    {
        client->is_authenticated = 1;
        sprintf(buffer, "Authentification réussie! Bienvenue %s\n", client->username);
        send_to_client(client->ssl, buffer);

        // Notifier les autres clients
        sprintf(buffer, "SERVER: %s a rejoint le chat\n", client->username);
        broadcast_message(buffer, -1);
    }
    else
    {
        sprintf(buffer, "Échec de l'authentification\n");
        send_to_client(client->ssl, buffer);
        close(client->socket);
        SSL_free(client->ssl);
        free(client);
        return NULL;
    }

    // Boucle principale de traitement des messages
    while ((bytes_received = SSL_read(client->ssl, buffer, BUFFER_SIZE)) > 0)
    {
        buffer[bytes_received] = '\0';
        buffer[strcspn(buffer, "\n")] = 0;

        if (strlen(buffer) == 0)
            continue;

        if (buffer[0] == '/')
        {
            handle_command(client, buffer);
        }
        else
        {
            // Message normal - diffusion à tous
            char broadcast_msg[BUFFER_SIZE + 100];
            sprintf(broadcast_msg, "%s: %s\n", client->username, buffer);
            broadcast_message(broadcast_msg, -1);
        }

        if (strcmp(buffer, "/quit") == 0)
        {
            break;
        }
    }

    // Nettoyage à la déconnexion
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (clients[i] == client)
        {
            clients[i] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    sprintf(buffer, "SERVER: %s a quitté le chat\n", client->username);
    broadcast_message(buffer, -1);

    close(client->socket);
    SSL_free(client->ssl);
    free(client);

    return NULL;
}

int main()
{
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    pthread_t thread_id;

    // Initialisation SSL
    ssl_context = init_ssl_context();
    if (!ssl_context)
    {
        fprintf(stderr, "Échec de l'initialisation SSL\n");
        return 1;
    }

    // Initialisation base de données
    if (init_database() != 0)
    {
        fprintf(stderr, "Échec de l'initialisation de la base de données\n");
        return 1;
    }

    // Création du socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1)
    {
        perror("socket");
        return 1;
    }

    // Configuration du socket
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind");
        return 1;
    }

    if (listen(server_fd, 10) < 0)
    {
        perror("listen");
        return 1;
    }

    printf("Serveur de chat SSL démarré sur le port %d\n", PORT);

    // Boucle principale d'acceptation des connexions
    while (1)
    {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0)
        {
            perror("accept");
            continue;
        }

        // Création du contexte SSL pour ce client
        SSL *ssl = SSL_new(ssl_context);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0)
        {
            ERR_print_errors_fp(stderr);
            close(client_fd);
            SSL_free(ssl);
            continue;
        }

        // Création de la structure client
        ClientInfo *client = malloc(sizeof(ClientInfo));
        client->socket = client_fd;
        client->ssl = ssl;
        client->is_authenticated = 0;
        inet_ntop(AF_INET, &client_addr.sin_addr, client->ip_address, INET_ADDRSTRLEN);
        client->port = ntohs(client_addr.sin_port);

        // Ajout du client à la liste
        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (!clients[i])
            {
                clients[i] = client;
                break;
            }
        }
        pthread_mutex_unlock(&clients_mutex);

        // Création du thread client
        pthread_create(&thread_id, NULL, handle_client, (void *)client);
        pthread_detach(thread_id);
    }

    // Nettoyage
    SSL_CTX_free(ssl_context);
    sqlite3_close(db);
    close(server_fd);

    return 0;
}
