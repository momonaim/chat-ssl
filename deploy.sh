#!/bin/bash
# deploy.sh

# CentOS 7/8
#sudo yum update -y

# Installation des dépendances
sudo yum groupinstall "Development Tools" -y
sudo yum install openssl-devel sqlite-devel -y

# Création des certificats SSL
make certificates

# Initialisation de la base de données
sqlite3 chat_app.db < users.sql

# Compilation
make clean
make all

# Création des groupes par défaut
sqlite3 chat_app.db <<EOF
INSERT OR IGNORE INTO groups (name, description) VALUES
('general', 'Général'),
('developers', 'Développeurs'),
('support', 'Support technique');
EOF

echo "Déploiement terminé!"
echo "Pour démarrer le serveur: ./server"
echo "Pour démarrer un client: ./client 127.0.0.1 8888"
echo "Pour exécuter les tests: ./test_chat.sh"