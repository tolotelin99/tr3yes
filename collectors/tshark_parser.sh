#!/bin/bash
INTERFACE=${1:-eth0}
echo "[*] Iniciando captura Tshark en $INTERFACE..."
tshark -i "$INTERFACE" -T json -e frame.time -e ip.src -e ip.dst -e tcp.port | tee -a network_logs.json
