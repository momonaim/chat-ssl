#!/bin/bash
# test_chat.sh

echo "=== Test de l'application de chat ==="

# Démarrage du serveur en arrière-plan
echo "Démarrage du serveur..."
./server &
SERVER_PID=$!
sleep 2

# Test de connexion avec netcat
echo "Test de connexion SSL..."
echo -e "test_user\\ntest_pass\\n/help\\n/quit\\n" | timeout 5 openssl s_client -connect localhost:8888 -quiet 2>/dev/null

if [ $? -eq 0 ]; then
    echo "✓ Test de connexion réussi"
else
    echo "✗ Test de connexion échoué"
fi

# Arrêt du serveur
kill $SERVER_PID 2>/dev/null

echo "=== Tests terminés ==="
