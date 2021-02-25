#!/usr/bin/env bash

if [ ! -f psk ] ; then

  wg genkey >seed.key
  wg pubkey <seed.key >seed.pub

  wg genkey >shoot.key
  wg pubkey <shoot.key >shoot.pub

  wg genpsk >psk
fi

SEEDKEY=`cat seed.key`
SEEDPUB=`cat seed.pub`
SHOOTKEY=`cat shoot.key`
SHOOTPUB=`cat shoot.pub`
PSK=`cat psk`

cat >seed.wg0.conf <<EOF
[Interface]
Address = 192.168.17.1/24
PrivateKey = ${SEEDKEY}
ListenPort = 10200

[Peer]
PublicKey = ${SHOOTPUB}
PresharedKey = ${PSK}
AllowedIPs = 192.168.17.2/32
EOF

# --------------------------

cat >shoot.wg0.conf <<EOF
[Interface]
Address = 192.168.17.2/24
PrivateKey = ${SHOOTKEY}

[Peer]
PublicKey = ${SEEDPUB}
PresharedKey = ${PSK}
AllowedIPs = 192.168.17.1/32
Endpoint = TBD
PersistentKeepalive = 21
EOF

# for seed
wg=$(base64 -w0 <seed.wg0.conf)

cat >wireguard-secret-seed.yaml <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: wireguard-secret
  namespace: wireguard
data:
  wg0.conf: ${wg}
EOF

# for shoot
wg=$(base64 -w0 <shoot.wg0.conf)

cat >wireguard-secret-shoot.yaml <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: wireguard-secret
  namespace: wireguard
data:
  wg0.conf: ${wg}
EOF

