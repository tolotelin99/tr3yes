#!/bin/bash
echo "[*] Conectando al demonio Kismet para captura inalámbrica..."
kismet_client --connect 127.0.0.1:2501 --json | tee -a wifi_logs.json
