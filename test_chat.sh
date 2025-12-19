#!/bin/bash
# test_chat.sh

echo "=== Test de l'application de chat ==="

# Démarrage du serveur en arrière-plan
echo "Démarrage du serveur..."
./server &
SERVER_PID=$!
sleep 2


# Test de connexion avec expect (pour interaction avec les invites)
echo "Test de connexion SSL..."
if ! command -v expect >/dev/null 2>&1; then
    echo "✗ 'expect' n'est pas installé. Installez-le pour exécuter ce test."
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

expect <<EOF
set timeout 5
spawn openssl s_client -connect localhost:8888 -quiet
expect "nom d'utilisateur:"
send "test_user\r"
expect "mot de passe:"
send "test_pass\r"
expect {
    "Bienvenue" { send "/help\r"; send "/quit\r"; }
    timeout { exit 1 }
}
expect eof
EOF

if [ $? -eq 0 ]; then
    echo "✓ Test de connexion réussi"
else
    echo "✗ Test de connexion échoué"
fi

# Arrêt du serveur
kill $SERVER_PID 2>/dev/null

echo "=== Tests terminés ==="
