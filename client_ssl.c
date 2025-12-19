// client_ssl.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 4096

SSL_CTX *ssl_context;
SSL *ssl;

void *receive_messages(void *arg)
{
    char buffer[BUFFER_SIZE];
    int bytes_received;

    while ((bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE)) > 0)
    {
        buffer[bytes_received] = '\0';
        printf("%s", buffer);
        fflush(stdout);
    }

    return NULL;
}

void init_ssl()
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ssl_context = SSL_CTX_new(SSLv23_client_method());
    if (!ssl_context)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    pthread_t recv_thread;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <server_ip> <port>\n", argv[0]);
        return 1;
    }

    init_ssl();

    // Création du socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("socket");
        return 1;
    }

    // Configuration du serveur
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(atoi(argv[2]));
    inet_pton(AF_INET, argv[1], &server_addr.sin_addr);

    // Connexion au serveur
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("connect");
        return 1;
    }

    // Configuration SSL
    ssl = SSL_new(ssl_context);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf("Connexion SSL établie avec le serveur\n");

    // Thread de réception des messages
    pthread_create(&recv_thread, NULL, receive_messages, NULL);

    // Boucle d'envoi des messages
    while (1)
    {
        fgets(buffer, BUFFER_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = 0;

        if (strlen(buffer) > 0)
        {
            strcat(buffer, "\n");
            SSL_write(ssl, buffer, strlen(buffer));

            if (strcmp(buffer, "/quit\n") == 0)
            {
                break;
            }
        }
    }

    // Nettoyage
    pthread_cancel(recv_thread);
    SSL_free(ssl);
    SSL_CTX_free(ssl_context);
    close(sock);

    return 0;
}
