# Makefile
CC = gcc -std=c99
CFLAGS = -Wall -g
LDFLAGS = -lpthread -lsqlite3 -lssl -lcrypto

all: server client test

server: server_ssl.c
	$(CC) $(CFLAGS) -o server server_ssl.c $(LDFLAGS)

client: client_ssl.c
	$(CC) $(CFLAGS) -o client client_ssl.c $(LDFLAGS)

certificates:
	openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/C=MA/ST=Settat/L=Settat/O=ChatApp/CN=localhost"

test: test_chat.sh server client
	chmod +x test_chat.sh
	./test_chat.sh

clean:
	rm -f server client *.o

clean-db:
	rm -f chat_app.db

run-server: server
	./server

run-client: client
	./client 127.0.0.1 8888
