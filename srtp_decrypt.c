// auf m Raspberry compilieren mit
// gcc -o srtp_decrypt_arm srtp_decrypt.c -lsrtp2 -lpcap -lcrypto
//
// https://www.quora.com/How-can-we-compile-the-x86-target-binaries-on-an-ARM-computer-from-C-C-source-code-Is-there-any-compilers-or-solutions-to-do-that
// x86_64-linux-gnu-gcc -o srtp_decrypt.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <srtp2/srtp.h>
#include <pcap/pcap.h>

// Fehlercodes: 0–99 = libsrtp, ab 100 eigene Codes
#define EXIT_OK                0
#define EXIT_ERR_ARGS         100  // Ungültige Kommandozeilenargumente
#define EXIT_ERR_OPEN_INPUT   101  // PCAP-Datei konnte nicht geöffnet werden
#define EXIT_ERR_OPEN_OUTPUT  102  // Ausgabedatei konnte nicht angelegt werden
#define EXIT_ERR_KEY_ISSUE    103  // Schlüssellänge nicht korrekt
#define EXIT_ERR_CREATE_SRTP  103  // SRTP-Session konnte nicht erstellt werden
#define EXIT_ERR_NO_PACKETS   104  // Keine verarbeiteten Pakete
#define EXIT_ERR_PARTIAL_FAIL 105  // Einige Pakete fehlgeschlagen
#define EXIT_ERR_FILE_WRITE   106  // Fehler beim Schreiben
#define EXIT_ERR_INIT_LIBSRTP 107  // Fehler beim initialisieren der SRTP-Session

static int verbose = 0;
srtp_err_status_t worst_srtp_error = srtp_err_status_ok;

// ====================== Hilfsfunktionen ==================
void verbose_log(const char *fmt, ...)
{
    if (!verbose) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

void hex_print(const char* label, const uint8_t* data, size_t len)
{
    if (!verbose) return;
    fprintf(stderr, "%s:", label);
    for (size_t i = 0; i < len; i++)
        fprintf(stderr, " %02x", data[i]);
    fprintf(stderr, "\n");
}

int parse_key(const char* hexkey, uint8_t* key, size_t expected_len)
{
    if (strlen(hexkey) != expected_len * 2)
    {
        fprintf(stderr, "Error: Key length is not %zu bytes (hex chars expected: %zu)\n", expected_len, expected_len * 2);
        return -1;
    }
    for (size_t i = 0; i < expected_len; i++)
    {
        unsigned int byte;
        if (sscanf(hexkey + 2 * i, "%2x", &byte) != 1)
        {
            fprintf(stderr, "Error: Invalid hex in key\n");
            return -1;
        }
        key[i] = (uint8_t)byte;
    }
    return 0;
}

// ====================== Hauptprogramm ==================
int main(int argc, char* argv[])
{
    if (argc < 4)
    {
        fprintf(stderr, "Usage: %s <key-hex> <input-file> <output-file> [-v]\n", argv[0]);
        return 1;
    }

    const char* key_hex = argv[1];
    const char* infile = argv[2];
    const char* outfile = argv[3];

    if (argc > 4 && strcmp(argv[4], "-v") == 0)
    {
        verbose = 1;
    }

    size_t key_len = strlen(key_hex) / 2;
    srtp_crypto_policy_t policy;
    int valid = 1;
    int failed_count;

    // Erkennung der Verschlüsselung
    switch (key_len)
    {
        case 30: // 16 + 14
            srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy);
            break;
        case 38: // 24 + 14
            srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80(&policy);
            break;
        case 46: // 32 + 14
            srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(&policy);
            break;
        default:
            fprintf(stderr, "Unsupported key length: %zu bytes (expected 30/38/46)\n", key_len);
//            exit(EXIT_ERR_KEY_ISSUE);
//            return 1;
            return (EXIT_ERR_KEY_ISSUE);
    }

    uint8_t key[key_len];
    if (parse_key(key_hex, key, key_len) != 0)
    {
        return 1;
    }
    verbose_log("Parsed key (%zu bytes)\n", key_len);
    hex_print("Key", key, key_len);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_in = pcap_open_offline(infile, errbuf);
    if (!pcap_in)
    {
        fprintf(stderr, "Fehler beim Öffnen der Eingabedatei mit pcap: %s\n", errbuf);
        return(EXIT_ERR_OPEN_INPUT);
//        exit(EXIT_ERR_OPEN_INPUT);
//        return 1;
    }

    // Erzeuge Output-Datei mit gleichem Linktype wie Input
    pcap_dumper_t *pcap_out = NULL;
    pcap_out = pcap_dump_open(pcap_in, outfile);
    if (!pcap_out)
    {
        fprintf(stderr, "Fehler beim Öffnen der Ausgabedatei: %s\n", pcap_geterr(pcap_in));
        pcap_close(pcap_in);
        return(EXIT_ERR_OPEN_OUTPUT);
//        exit(EXIT_ERR_OPEN_OUTPUT);
//        return 1;
    }

    // Init libsrtp
    if (srtp_init() != srtp_err_status_ok)
    {
        fprintf(stderr, "Error initializing libsrtp\n");
        pcap_close(pcap_in);
        return(EXIT_ERR_INIT_LIBSRTP);
//        exit(EXIT_ERR_INIT_LIBSRTP);
//        return 1;
    }

    srtp_policy_t policy_struct;
    memset(&policy_struct, 0, sizeof(policy_struct));
    policy_struct.ssrc.type = ssrc_any_inbound;
    policy_struct.key = key;
    policy_struct.rtp = policy;
    policy_struct.rtcp = policy;
    policy_struct.next = NULL;

    srtp_t session;
    if (srtp_create(&session, &policy_struct) != srtp_err_status_ok)
    {
        fprintf(stderr, "Error creating SRTP session\n");
        srtp_shutdown();
        pcap_close(pcap_in);
        return(EXIT_ERR_CREATE_SRTP);
//        exit(EXIT_ERR_CREATE_SRTP);
//        return 1;
    }
    else
    {
        verbose_log("SRTP session created\n");
    }

    const u_char *packet;
    struct pcap_pkthdr *header;
    int packet_count = 0, success_count = 0;
    const int rtp_offset = 42; // Ethernet + IP + UDP header (abschätzungsweise)

    // Entschlüsselung
    while (pcap_next_ex(pcap_in, &header, &packet) > 0)
    {
        packet_count++;

        if ((size_t)header->caplen <= rtp_offset)
            continue;

        // Original SRTP-Daten (ab RTP-Offset)
        uint8_t *srtp_data = (uint8_t *)(packet + rtp_offset);
        int srtp_len = header->caplen - rtp_offset;

        srtp_err_status_t err = srtp_unprotect(session, srtp_data, &srtp_len);

        if (err == srtp_err_status_ok)
        {
            // Ersetze das Payload im Originalpaket mit entschlüsseltem
            size_t new_len = rtp_offset + srtp_len;
            uint8_t *new_packet = malloc(new_len);
            if (!new_packet)
            {
                fprintf(stderr, "Speicherfehler bei SRTP-Paket-Allokation\n");
                continue;
            }

            memcpy(new_packet, packet, rtp_offset);
            memcpy(new_packet + rtp_offset, srtp_data, srtp_len);

            // Korrektur IP-Header: Total Length (Offset 16)
            uint16_t ip_total_len = htons(20 + 8 + srtp_len); // IP+UDP+RTP
            memcpy(new_packet + 16, &ip_total_len, 2);

            // Korrektur UDP-Header: Length (Offset 42+4)
            uint16_t udp_len = htons(8 + srtp_len);
            memcpy(new_packet + 38, &udp_len, 2);


            // UDP Checksum auf 0 setzen (Offset 42+6)
            memset(new_packet + 40, 0, 2);


            // Neue Header-Länge setzen
            struct pcap_pkthdr new_hdr = *header;
            new_hdr.caplen = new_hdr.len = new_len;

            pcap_dump((u_char *)pcap_out, &new_hdr, new_packet);
            free(new_packet);
            success_count++;
            if (packet_count == 1)
            {
                verbose_log("ip_total_len: %d, srtp_len: %d, udp_len: %d, new_len: %d\n", ntohs(ip_total_len), srtp_len, ntohs(udp_len), new_len);
            }
        }
        else
        {
//            if (worst_srtp_error == srtp_err_status_ok || err > worst_srtp_error)
            if (err > worst_srtp_error)
                worst_srtp_error = err;
//            continue;
            verbose_log("\nsrtp_unprotect Fehler bei Paket #%d: Code %d", packet_count, err);
            failed_count++;
            continue; 
        }

        // Ausgabe Fortschritt
        if (packet_count == 1 || packet_count % 100 == 0)
        {
            printf(".");
            fflush(stdout);  // Damit der Punkt sofort sichtbar wird
        }
    }
    fprintf(stderr, "\n");
    verbose_log("Pakete verarbeitet: %d, erfolgreich entschlüsselt: %d, fehlgeschlagen: %d\n", packet_count, success_count, failed_count++);

    // Datei schließen
    verbose_log("versuche Dateien zu schließen\n");
    pcap_dump_close(pcap_out);
    pcap_close(pcap_in);
    verbose_log("Dateien geschlossen\n");
    verbose_log("Ergebnis geschrieben nach '%s'\n", outfile);

    verbose_log("Sessions und Speicher freigeben\n");
    srtp_dealloc(session);
    srtp_shutdown();

    if (worst_srtp_error != srtp_err_status_ok)
        fprintf(stderr, "SRTPLIB ERRORCODE %d\n", worst_srtp_error);

    if (success_count == 0)
    {
        fprintf(stderr, "❌ Keine Pakete erfolgreich entschlüsselt.\n");
        return(worst_srtp_error);
//        exit(worst_srtp_error);
//        exit(EXIT_ERR_NO_PACKETS);
    }
    else
        if (failed_count > 0)
        {
            fprintf(stderr, "⚠️ %d Pakete fehlgeschlagen (gesamt: %d)\n", failed_count, packet_count);
            return(worst_srtp_error);
//            exit(worst_srtp_error);
//            exit(EXIT_ERR_PARTIAL_FAIL);
        }
        else
        {
            return(EXIT_OK);
//            exit(EXIT_OK);
        }
}

