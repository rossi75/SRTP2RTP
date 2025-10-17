#!/bin/bash
set -euo pipefail

# -------------------- Konfiguration & Hilfsfunktionen --------------------
VERBOSE=0
ELEVATED="${ELEVATED:-0}"
SUMMARY_FILE="srtp_decrypt_summary.log"
COMMAND_OUTPUT=""
EXIT_CODE=0

log()
{
  if [[ "$VERBOSE" -eq 1 ]]; then
    echo "[verbose] $*"
  fi
}

run()
{
  [[ "$VERBOSE" -eq 1 ]] && echo ">> $*"
  set +e
  local CMD="$1"
  COMMAND_OUTPUT=$(eval "$CMD" 2>&1 1>/dev/tty)
  EXIT_CODE=$?
  set -e
}


# -------------------- Architektur erkennen --------------------
ARCH=$(uname -m)

case "$ARCH" in
  x86_64)
    BINARY="./srtp_decrypt_x86"
    ;;
  aarch64 | arm64 | armv7l | armv6l)
    BINARY="./srtp_decrypt_arm"
    ;;
  *)
    echo "❌ Nicht unterstützte Architektur: $ARCH"
    exit 99
    ;;
esac

# Prüfen, ob Binary existiert und ausführbar ist
if [[ ! -x "$BINARY" ]]; then
  echo "❌ Binary für Architektur '$ARCH' nicht gefunden oder nicht ausführbar: $BINARY"
  exit 98
fi


# -------------------- Argumentverarbeitung --------------------
POSITIONAL=()
for arg in "$@"; do
  case "$arg" in
    -v) VERBOSE=1 ;;
    *)  POSITIONAL+=("$arg") ;;
  esac
done
set -- "${POSITIONAL[@]}"

if [ $# -lt 1 ]; then
  echo "Usage: $0 [-v] <pcap_file>"
  exit 1
fi


# -------------------- Anzeige Informationen --------------------
[[ "$VERBOSE" -eq 1 ]] && echo ">>> Verbose Modus aktiv !! <<<"


# -------------------- Eingabedatei prüfen --------------------
PCAP="$1"
if [ ! -f "$PCAP" ]; then
  echo "❌ Datei '$PCAP' nicht gefunden."
  exit 3
elif [[ "$VERBOSE" -eq 1 ]]; then
  echo "   '$PCAP' ist vorhanden"
fi


# -------------------- UDP-Streams finden --------------------
echo ""
echo "🔍 in '$PCAP' gefundene UDP-Streams:"
#run "mapfile -t streams < <(tshark -r "$PCAP" -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport | sort | uniq -c)"

[[ "$VERBOSE" -eq 1 ]] && echo ">>(tshark -r \"$PCAP\" -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport | sort | uniq -c)"
streams=()
while IFS= read -r line; do
  streams+=("$line")
done < <(tshark -r "$PCAP" -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport | sort | uniq -c)

echo "$COMMAND_OUTPUT"

for i in "${!streams[@]}"; do
  count=$(echo "${streams[$i]}" | awk '{print $1}')
  SRC_IP=$(echo "${streams[$i]}" | awk '{print $2}')
  SRC_PORT=$(echo "${streams[$i]}" | awk '{print $3}')
  DST_IP=$(echo "${streams[$i]}" | awk '{print $4}')
  DST_PORT=$(echo "${streams[$i]}" | awk '{print $5}')

  printf "   [%d]  %-6s  %s:%s --> %s:%s\n" $((i+1)) "$count" "$SRC_IP" "$SRC_PORT" "$DST_IP" "$DST_PORT"
done

echo -e "\a"
read -rp "   Welche Streams sollen entschlüsselt werden? (z.B. 1 3 5): " -a choices


# -------------------- Key-Eingabe --------------------
declare -A STREAM_META
declare -A STREAM_KEYS
declare -A STREAM_KEYS_RX

for choice in "${choices[@]}"; do
  if ! [[ "$choice" =~ ^[0-9]+$ ]] || ((choice < 1 || choice > ${#streams[@]})); then
    echo "⚠️  Ungültige Auswahl: $choice. Überspringe."
    continue
  fi

  line="${streams[$((choice-1))]}"
  SRC_IP=$(echo "$line" | awk '{print $2}')
  SRC_PORT=$(echo "$line" | awk '{print $3}')
  DST_IP=$(echo "$line" | awk '{print $4}')
  DST_PORT=$(echo "$line" | awk '{print $5}')

  echo ""
  echo "➡️  Stream $choice: $SRC_IP:$SRC_PORT → $DST_IP:$DST_PORT"

  set +e

  # Algorithmus | AES-Key Bytes + Salt Bytes = Gesamt Bytes | Base64 Bytes | HEX Bytes |
  # ----------- | ------------- | ---------- | ------------ | ------------ | --------- |
  # AES-128     |      16       +     14     =      30      |      40      |    60     |
  # AES-192     |      24       +     14     =      38      |      52      |    76     |
  # AES-256     |      32       +     14     =      46      |      64      |    92     |

  while true; do
    echo "    SRTP-Key eingeben ([inline:[40|52|64 Zeichen]] oder Hex [60|76|92 Zeichen]):"
    read -rp "    Key: " KEY_INPUT
    KEY_INPUT=$(echo "$KEY_INPUT" | sed -E 's/^[Ii][Nn][Ll][Ii][Nn][Ee]://')
    KEY_LEN=${#KEY_INPUT}

    case ${KEY_LEN} in
      # --- HEX ---
      60)  # 30 Bytes (16x AES-128 + 14x salt)
        PROFILE="AES_CM_128_HMAC_SHA1_80 [HEX]"
        KEY="$KEY_INPUT"
        ;;
      76)  # 38 Bytes (24x AES-192 + 14x salt)
        PROFILE="AES_CM_192_HMAC_SHA1_80 [HEX]"
        KEY="$KEY_INPUT"
        ;;
      92)  # 46 Bytes (32x AES-256 + 14x salt)
        PROFILE="AES_CM_256_HMAC_SHA1_80 [HEX]"
        KEY="$KEY_INPUT"
        ;;
      # --- Base64 ---
#      44)  # entspricht 30 Bytes
      40)  # entspricht 30 Bytes
        PROFILE="AES_CM_128_HMAC_SHA1_80 [Base64]"
        KEY=$(echo "$KEY_INPUT" | base64 -d 2>/dev/null | xxd -p | tr -d '\n')
        ;;
      52)  # entspricht 38 Bytes
        PROFILE="AES_CM_192_HMAC_SHA1_80 [Base64]"
        KEY=$(echo "$KEY_INPUT" | base64 -d 2>/dev/null | xxd -p | tr -d '\n')
        ;;
      64)  # entspricht 46 Bytes
        PROFILE="AES_CM_256_HMAC_SHA1_80 [Base64]"
        KEY=$(echo "$KEY_INPUT" | base64 -d 2>/dev/null | xxd -p | tr -d '\n')
        ;;
      *)
        echo "❌ Ungültige Schlüssellänge von ($KEY_LEN) Zeichen erkannt. Erwartet:"
        echo "   HEX: 60/76/92 Zeichen"
        echo "   Base64: 40/52/64 Zeichen"
        continue
    esac

    echo "     ✅ $PROFILE erkannt"

    break
  done
  ID="stream_$choice"
  STREAM_META["$ID"]="$SRC_IP:$SRC_PORT->$DST_IP:$DST_PORT"
  STREAM_KEYS["$ID"]="$KEY"
done

if [[ ${#STREAM_META[@]} -eq 0 ]]; then
  echo "❌ Keine gültigen Streams ausgewählt. Abbruch."
  exit 1
fi


# -------------------- Zusammenfassung --------------------
{
  echo "========== Entschlüsselungsdurchlauf – $(date '+%d.%m.%Y %H:%M:%S') =========="
  echo "  Datei     : $PCAP"
  i=1
  for id in "${!STREAM_META[@]}"; do
    echo "  [$i]"
    printf "    %-8s: %s\n" "Stream" "${STREAM_META[$id]}"
    printf "    %-8s: %s\n" "Key"    "${STREAM_KEYS[$id]}"
    ((i++))
  done
} >> "$SUMMARY_FILE"

echo ""
echo "📝 Zusammenfassung:"
echo "-------------------------------"
echo "  Datei     : ${PCAP}"
i=1
for id in "${!STREAM_META[@]}"; do
  echo "  [$i]"
  printf "    %-8s: %s\n" "Stream" "${STREAM_META[$id]}"
  printf "    %-8s: %s\n" "TX-Key" "${STREAM_KEYS[$id]}"
  ((i++))
done


# -------------------- Entschlüsselung --------------------
for id in "${!STREAM_META[@]}"; do
  stream="${STREAM_META[$id]}"
  stream_nop="${stream//->/ }"
  read -r SRC DST <<<"$stream_nop"
  SRC_IP="${SRC%:*}"
  SRC_PORT="${SRC#*:}"
  DST_IP="${DST%:*}"
  DST_PORT="${DST#*:}"

  RAW="srtp_${SRC_IP}_${SRC_PORT}_to_${DST_IP}_${DST_PORT}.pcap"
  RTP="rtp_${SRC_IP}_${SRC_PORT}_to_${DST_IP}_${DST_PORT}.pcap"

  echo ""
  echo "🔄 Extrahiere: $SRC_IP:$SRC_PORT → $DST_IP:$DST_PORT"
  FILTER="udp and src host $SRC_IP and src port $SRC_PORT and dst host $DST_IP and dst port $DST_PORT"
  [[ "$VERBOSE" -eq 1 ]] && echo ">>   tcpdump filter: $FILTER"
  run "tcpdump -nn -r \"$PCAP\" -w \"$RAW\" \"$FILTER\" "

  echo "   Starte Entschlüsselung mit TX_KEY"
  #set -x
  if [[ "$VERBOSE" -eq 1 ]]; then
    run "$BINARY ${STREAM_KEYS[$id]} \"$RAW\" \"$RTP\" -v"
    echo "Ausgabe srtp_decrypt: $COMMAND_OUTPUT, $EXIT_CODE"
    SRTP_ERR_CODE=$EXIT_CODE
  else
    run "$BINARY ${STREAM_KEYS[$id]} \"$RAW\" \"$RTP\""
    echo "$COMMAND_OUTPUT"
    SRTP_ERR_CODE=$EXIT_CODE
  fi

  if [[ $SRTP_ERR_CODE -eq 0 ]]; then
    echo "✅ Entschlüsselung erfolgreich: $RTP"
    {
      echo "    ------> Stream [$id] erfolgreich entschlüsselt <------"
    } >> "$SUMMARY_FILE"
  else
    # Fehlercode extrahieren und übersetzen
#    if [[ "$DECRYPT_OUTPUT" =~ Fehler\ bei\ srtp_unprotect:\ ([0-9]+) ]]; then
#      SRTP_ERR_CODE="${BASH_REMATCH[1]}"
#      SRTP_ERROR_MSG=""
    echo ""

    case "$SRTP_ERR_CODE" in
      0)  SRTP_ERROR_MSG="🟢 OK (srtp_err_status_ok)" ;;
      1)  SRTP_ERROR_MSG="🔴 FAIL (srtp_err_status_fail)" ;;
      3)  SRTP_ERROR_MSG="⚠️  BAD PARAMETER (srtp_err_status_bad_param)" ;;
      4)  SRTP_ERROR_MSG="⚠️  ALLOC FAILURE (srtp_err_status_alloc_fail)" ;;
      6)  SRTP_ERROR_MSG="🚫 DECRYPT FAILURE (srtp_err_status_decrypt_fail)" ;;
      7)  SRTP_ERROR_MSG="🚫 AUTH FAILURE (srtp_err_status_auth_fail)" ;;
      9)  SRTP_ERROR_MSG="⚠️  REPLAY FAIL (srtp_err_status_replay_fail)" ;;
      10) SRTP_ERROR_MSG="⚠️  REPLAY OLD PACKET (srtp_err_status_replay_old)" ;;
      13) SRTP_ERROR_MSG="⚠️  CIPHER FAILURE (srtp_err_status_cipher_fail)" ;;
      14) SRTP_ERROR_MSG="⚠️  NO SUCH OPERATION (srtp_err_status_no_such_op)" ;;
      21) SRTP_ERROR_MSG="🔒 UNSUPPORTED CIPHER SUITE" ;;
      *)  SRTP_ERROR_MSG="❓ Unbekannter Fehlercode: $SRTP_ERR_CODE" ;;
    esac
    echo "❌ Entschlüsselung fehlgeschlagen für Stream [$id]: ${STREAM_META[$id]}"
#     echo "🔍 Fehler: $SRTP_ERROR_MSG [$DECRYPT_ERROR_OUTPUT]"
    echo "🔍 Fehler: $SRTP_ERROR_MSG [$SRTP_ERR_CODE]"
#     echo " Fehler: $SRTP_ERROR_MSG [$DECRYPT_ERROR_OUTPUT]" >> "$SUMMARY_FILE"
    echo " Fehler: $SRTP_ERROR_MSG [$SRTP_ERR_CODE]" >> "$SUMMARY_FILE"
    echo -e "\n" >> "$SUMMARY_FILE"

  fi
done


# -------------------- Fertig --------------------
echo -e "\n" >> "$SUMMARY_FILE"
echo "🗒️  Zusammenfassung gespeichert in: $SUMMARY_FILE"
echo -e "\n"
