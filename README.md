# Chat SSL

Ce projet est une application de chat sécurisée utilisant SSL pour la communication entre clients et serveur.

## Fonctionnalités

- Authentification des utilisateurs
- Messagerie de groupe et privée
- Commandes pour rejoindre/quitter des groupes
- Liste des utilisateurs et groupes actifs
- Communication chiffrée via SSL
- Commandes rapides :
  - `/g <message>` : envoyer un message au groupe
  - `/p <utilisateur> <message>` : envoyer un message privé
  - `/h` : afficher l'aide
  - `/q` : quitter

## Fichiers principaux

- `server_ssl.c` : serveur de chat SSL
- `client_ssl.c` : client de chat SSL
- `users.sql` : script SQL pour la gestion des utilisateurs
- `Makefile` : compilation
- `deploy.sh` : script de déploiement
- `test_chat.sh` : script de test

## Compilation

```sh
make
```

## Cetifications

```sh
make certificates
```

## Lancement du serveur

```sh
./server_ssl
```

## Lancement du client

```sh
./client_ssl
```

## Dépendances

- OpenSSL
- pthread
- sqlite3
