#!/bin/sh
# Nyalakan lab Juice Shop hanya di loopback, lalu buktikan port tidak terbuka ke jaringan.
# Kalau pembuktian gagal, kontainer dihentikan.
# AKU SUKA HAURA
set -eu

NAME=juice-shop
PORT=3000
IMAGE=mirror.gcr.io/bkimminich/juice-shop@sha256:877fc77b12d72b42e486eb09b6b1711cc56514306d92006b284e7e7cf076a809
D="sudo docker"

fail() {
    echo "lab-up: $1" >&2
    $D stop "$NAME" >/dev/null 2>&1 || true
    exit 1
}

if $D inspect "$NAME" >/dev/null 2>&1; then
    bindings=$($D inspect -f '{{json .HostConfig.PortBindings}}' "$NAME")
    case "$bindings" in
        *'"HostIp":"127.0.0.1"'*) ;;
        *) echo "lab-up: kontainer $NAME tidak terikat ke 127.0.0.1 ($bindings). Hapus: $D rm -f $NAME" >&2; exit 1 ;;
    esac
    case "$bindings" in
        *'"HostIp":""'* | *'"HostIp":"0.0.0.0"'*) echo "lab-up: ada pengikatan terbuka. Hapus: $D rm -f $NAME" >&2; exit 1 ;;
    esac
    [ "$($D inspect -f '{{.State.Running}}' "$NAME")" = "true" ] || $D start "$NAME" >/dev/null
else
    $D run -d --name "$NAME" -p "127.0.0.1:$PORT:$PORT" "$IMAGE" >/dev/null
fi

ready=0
for _ in $(seq 1 30); do
    if curl -s --max-time 2 -o /dev/null "http://127.0.0.1:$PORT"; then ready=1; break; fi
    sleep 2
done
[ "$ready" = 1 ] || fail "tidak siap dalam 60 detik. Lihat: $D logs --tail 30 $NAME"

listeners=$(ss -ltnH "sport = :$PORT" | awk '{print $4}')
[ -n "$listeners" ] || fail "tidak ada yang mendengarkan di port $PORT"
for addr in $listeners; do
    [ "$addr" = "127.0.0.1:$PORT" ] || fail "port $PORT terbuka di $addr, bukan hanya loopback. Kontainer dihentikan"
done

for ip in $(hostname -I); do
    case "$ip" in *:* | 127.*) continue ;; esac
    if curl -s --max-time 3 -o /dev/null "http://$ip:$PORT"; then
        fail "lab terjangkau dari $ip. Kontainer dihentikan"
    fi
done

echo "lab siap: http://127.0.0.1:$PORT/ (hanya loopback, tidak terjangkau dari LAN)"
