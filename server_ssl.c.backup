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
    char group[50]; // Added for group chat
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

    // Disable insecure SSL/TLS versions
    SSL_CTX_set_options(ctx,
                        SSL_OP_NO_SSLv2 |
                            SSL_OP_NO_SSLv3 |
                            SSL_OP_NO_TLSv1 |
                            SSL_OP_NO_TLSv1_1);

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
        fseek(sql_file, 0, SEEK_END);
        long file_size = ftell(sql_file);
        rewind(sql_file);
        char *sql_script = malloc(file_size + 1);
        if (sql_script)
        {
            size_t read_size = fread(sql_script, 1, file_size, sql_file);
            sql_script[read_size] = '\0';
            char *err_msg = 0;
            rc = sqlite3_exec(db, sql_script, 0, 0, &err_msg);
            if (rc != SQLITE_OK)
            {
                fprintf(stderr, "SQL error: %s\n", err_msg);
                sqlite3_free(err_msg);
            }
            free(sql_script);
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

    // WARNING: In production, use a secure password hash (e.g., bcrypt) instead of plain text!
    sprintf(sql, "SELECT id, password_hash FROM users WHERE username = ?");

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK)
    {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) == SQLITE_ROW)
        {
            // Vérifier le mot de passe (simplifié - utiliser bcrypt en production)
            const char *stored_hash = (const char *)sqlite3_column_text(stmt, 1);
            // TODO: Use a secure hash comparison in production
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
    if (!token)
        return;

    // Shortcuts: /g = /group, /p = /private, /h = /help, /q = /quit
    if (strcmp(token, "/g") == 0)
        token = "/group";
    else if (strcmp(token, "/p") == 0)
        token = "/private";
    else if (strcmp(token, "/h") == 0)
        token = "/help";
    else if (strcmp(token, "/q") == 0)
        token = "/quit";
    else if (strcmp(token, "/j") == 0)
        token = "/join";

    if (strcmp(token, "/join") == 0)
    {
        token = strtok(NULL, " ");
        if (!token)
        {
            snprintf(buffer, sizeof(buffer), "SERVER: Groupe non spécifié\n");
        }
        else
        {
            strncpy(client->group, token, sizeof(client->group) - 1);
            client->group[sizeof(client->group) - 1] = '\0';
            snprintf(buffer, sizeof(buffer), "SERVER: Vous avez rejoint le groupe %s\n", client->group);
        }
        send_to_client(client->ssl, buffer);
    }
    else if (strcmp(token, "/leave") == 0)
    {
        if (client->group[0] == '\0')
        {
            snprintf(buffer, sizeof(buffer), "SERVER: Vous n'êtes dans aucun groupe.\n");
        }
        else
        {
            client->group[0] = '\0';
            snprintf(buffer, sizeof(buffer), "SERVER: Vous avez quitté le groupe.\n");
        }
        send_to_client(client->ssl, buffer);
    }
    else if (strcmp(token, "/group") == 0)
    {
        char *message = strtok(NULL, "");
        if (!client->group[0])
        {
            snprintf(buffer, sizeof(buffer), "SERVER: Vous n'avez pas rejoint de groupe. Utilisez /join [groupe]\n");
            send_to_client(client->ssl, buffer);
            return;
        }
        if (!message || strlen(message) == 0)
        {
            snprintf(buffer, sizeof(buffer), "SERVER: Message de groupe vide. Usage: /group [message]\n");
            send_to_client(client->ssl, buffer);
            return;
        }
        char group_msg[BUFFER_SIZE + 100];
        snprintf(group_msg, sizeof(group_msg), "[GROUPE %s] %s: %s\n", client->group, client->username, message);
        // Broadcast only to group members
        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (clients[i] && clients[i]->is_authenticated && strcmp(clients[i]->group, client->group) == 0)
            {
                send_to_client(clients[i]->ssl, group_msg);
            }
        }
        pthread_mutex_unlock(&clients_mutex);
    }
    else if (strcmp(token, "/private") == 0)
    {
        char *target_user = strtok(NULL, " ");
        char *message = strtok(NULL, "\n");
        if (!target_user || !message)
        {
            snprintf(buffer, sizeof(buffer), "SERVER: Usage: /private [user] [message]\n");
            send_to_client(client->ssl, buffer);
            return;
        }
        snprintf(buffer, sizeof(buffer), "PRIVATE from %s: %s\n", client->username, message);

        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (clients[i] && clients[i]->username[0] != '\0' && strcmp(clients[i]->username, target_user) == 0)
            {
                send_to_client(clients[i]->ssl, buffer);
                break;
            }
        }
        pthread_mutex_unlock(&clients_mutex);
    }
    else if (strcmp(token, "/users") == 0)
    {
        size_t pos = 0;
        int n;
        n = snprintf(buffer + pos, sizeof(buffer) - pos, "=== Utilisateurs connectés ===\n");
        if (n < 0 || (size_t)n >= sizeof(buffer) - pos)
            n = (int)(sizeof(buffer) - pos - 1);
        pos += n;
        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (clients[i] && clients[i]->is_authenticated && clients[i]->username[0] != '\0')
            {
                n = snprintf(buffer + pos, sizeof(buffer) - pos, "- %s (%s:%d)\n",
                             clients[i]->username, clients[i]->ip_address, clients[i]->port);
                if (n < 0 || (size_t)n >= sizeof(buffer) - pos)
                {
                    // Buffer full, stop adding more users
                    break;
                }
                pos += n;
            }
        }
        pthread_mutex_unlock(&clients_mutex);
        buffer[sizeof(buffer) - 1] = '\0';
        send_to_client(client->ssl, buffer);
    }
    else if (strcmp(token, "/groups") == 0)
    {
        char groups[MAX_CLIENTS][50];
        int group_count = 0;
        size_t pos = 0;
        int n;
        n = snprintf(buffer + pos, sizeof(buffer) - pos, "=== Groupes actifs ===\n");
        if (n < 0 || (size_t)n >= sizeof(buffer) - pos)
            n = (int)(sizeof(buffer) - pos - 1);
        pos += n;
        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (clients[i] && clients[i]->is_authenticated && clients[i]->group[0] != '\0')
            {
                int exists = 0;
                for (int j = 0; j < group_count; j++)
                {
                    if (strcmp(groups[j], clients[i]->group) == 0)
                    {
                        exists = 1;
                        break;
                    }
                }
                if (!exists && group_count < MAX_CLIENTS)
                {
                    strncpy(groups[group_count], clients[i]->group, sizeof(groups[group_count]) - 1);
                    groups[group_count][sizeof(groups[group_count]) - 1] = '\0';
                    group_count++;
                }
            }
        }
        pthread_mutex_unlock(&clients_mutex);
        for (int i = 0; i < group_count; i++)
        {
            n = snprintf(buffer + pos, sizeof(buffer) - pos, "- %s\n", groups[i]);
            if (n < 0 || (size_t)n >= sizeof(buffer) - pos)
            {
                break;
            }
            pos += n;
        }
        buffer[sizeof(buffer) - 1] = '\0';
        send_to_client(client->ssl, buffer);
    }
    else if (strcmp(token, "/help") == 0)
    {
        snprintf(buffer, sizeof(buffer), "=== Commandes disponibles ===\n"
                                         "/join [groupe] ou /j [groupe] - Rejoindre un groupe\n"
                                         "/leave - Quitter le groupe\n"
                                         "/group [message] ou /g [message] - Envoyer un message au groupe\n"
                                         "/groups - Liste des groupes actifs\n"
                                         "/private [user] [message] ou /p [user] [message] - Message privé\n"
                                         "/users - Liste des utilisateurs\n"
                                         "/help ou /h - Afficher l'aide\n"
                                         "/quit ou /q - Quitter\n");
        send_to_client(client->ssl, buffer);
    }
    else if (strcmp(token, "/quit") == 0)
    {
        snprintf(buffer, sizeof(buffer), "SERVER: Déconnexion demandée. Au revoir !\n");
        send_to_client(client->ssl, buffer);
        SSL_shutdown(client->ssl);
        close(client->socket);
        SSL_free(client->ssl);
        free(client);
        pthread_exit(NULL);
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

    bytes_received = SSL_read(client->ssl, buffer, BUFFER_SIZE - 1);
    if (bytes_received <= 0)
    {
        close(client->socket);
        SSL_free(client->ssl);
        free(client);
        return NULL;
    }
    buffer[bytes_received] = '\0';
    buffer[strcspn(buffer, "\n")] = 0;
    strncpy(client->username, buffer, sizeof(client->username) - 1);
    client->username[sizeof(client->username) - 1] = '\0';
    client->group[0] = '\0'; // No group by default

    sprintf(buffer, "Entrez votre mot de passe: ");
    send_to_client(client->ssl, buffer);

    bytes_received = SSL_read(client->ssl, buffer, BUFFER_SIZE - 1);
    if (bytes_received <= 0)
    {
        close(client->socket);
        SSL_free(client->ssl);
        free(client);
        return NULL;
    }
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
        sprintf(buffer, "ERREUR: Échec de l'authentification. Connexion fermée.\n");
        send_to_client(client->ssl, buffer);
        // Shutdown SSL connection before closing
        SSL_shutdown(client->ssl);
        close(client->socket);
        SSL_free(client->ssl);
        free(client);
        pthread_exit(NULL);
    }

    // Boucle principale de traitement des messages
    while ((bytes_received = SSL_read(client->ssl, buffer, BUFFER_SIZE - 1)) > 0)
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
            // Message normal - diffusion à tous si pas dans un groupe
            char broadcast_msg[BUFFER_SIZE + 100];
            if (client->group[0] == '\0')
            {
                snprintf(broadcast_msg, sizeof(broadcast_msg), "%s: %s\n", client->username, buffer);
                broadcast_message(broadcast_msg, -1);
            }
            else
            {
                snprintf(broadcast_msg, sizeof(broadcast_msg), "[GROUPE %s] %s: %s\n", client->group, client->username, buffer);
                pthread_mutex_lock(&clients_mutex);
                for (int i = 0; i < MAX_CLIENTS; i++)
                {
                    if (clients[i] && clients[i]->is_authenticated && strcmp(clients[i]->group, client->group) == 0)
                    {
                        send_to_client(clients[i]->ssl, broadcast_msg);
                    }
                }
                pthread_mutex_unlock(&clients_mutex);
            }
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

        fprintf(stderr, "[DEBUG] Accepted new connection.\n");

        // Création du contexte SSL pour ce client
        SSL *ssl = SSL_new(ssl_context);
        if (!ssl)
        {
            fprintf(stderr, "[ERROR] SSL_new failed.\n");
            close(client_fd);
            continue;
        }
        if (SSL_set_fd(ssl, client_fd) == 0)
        {
            fprintf(stderr, "[ERROR] SSL_set_fd failed.\n");
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        if (SSL_accept(ssl) <= 0)
        {
            ERR_print_errors_fp(stderr);
            close(client_fd);
            SSL_free(ssl);
            continue;
        }

        fprintf(stderr, "[DEBUG] SSL handshake successful.\n");

        // Création de la structure client
        ClientInfo *client = malloc(sizeof(ClientInfo));
        if (!client)
        {
            fprintf(stderr, "Erreur d'allocation mémoire pour ClientInfo\n");
            close(client_fd);
            SSL_free(ssl);
            continue;
        }
        memset(client, 0, sizeof(ClientInfo));
        client->socket = client_fd;
        client->ssl = ssl;
        client->is_authenticated = 0;
        if (!inet_ntop(AF_INET, &client_addr.sin_addr, client->ip_address, INET_ADDRSTRLEN))
        {
            fprintf(stderr, "[ERROR] inet_ntop failed.\n");
            close(client_fd);
            SSL_free(ssl);
            free(client);
            continue;
        }
        client->port = ntohs(client_addr.sin_port);

        // Ajout du client à la liste
        pthread_mutex_lock(&clients_mutex);
        int added = 0;
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (!clients[i])
            {
                clients[i] = client;
                added = 1;
                break;
            }
        }
        pthread_mutex_unlock(&clients_mutex);
        if (!added)
        {
            fprintf(stderr, "[ERROR] Max clients reached.\n");
            close(client_fd);
            SSL_free(ssl);
            free(client);
            continue;
        }

        // Création du thread client
        int thread_result = pthread_create(&thread_id, NULL, handle_client, (void *)client);
        if (thread_result != 0)
        {
            fprintf(stderr, "[ERROR] pthread_create failed.\n");
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
            close(client_fd);
            SSL_free(ssl);
            free(client);
            continue;
        }
        pthread_detach(thread_id);
        fprintf(stderr, "[DEBUG] Client thread created and detached.\n");
    }

    // Nettoyage
    // Free all client memory
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (clients[i])
        {
            close(clients[i]->socket);
            SSL_free(clients[i]->ssl);
            free(clients[i]);
            clients[i] = NULL;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    SSL_CTX_free(ssl_context);
    sqlite3_close(db);
    close(server_fd);

    return 0;
}
