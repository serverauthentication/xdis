#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

#include "dbg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    GDB_DEF_TIMEOUT = 2500,
    GDB_MAX_RETRY   = 3,
    GDB_MEM_CHUNK   = 512,
    GDB_WR_CHUNK    = 256
};

static int g_wsa_ok = 0;

static void gdb_err(gdb_ctx *g, const char *msg, int code) {
    if (!g) return;
    if (code)
        snprintf(g->last_err, sizeof(g->last_err), "%s (wsa %d)", msg, code);
    else
        snprintf(g->last_err, sizeof(g->last_err), "%s", msg);
}

static int gdb_hex_val(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static bool gdb_wsa_init(gdb_ctx *g) {
    if (g_wsa_ok) return true;
    WSADATA wsa;
    int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (rc != 0) {
        gdb_err(g, "WSAStartup failed", rc);
        return false;
    }
    g_wsa_ok = 1;
    return true;
}

static void gdb_set_rcv_timeout(SOCKET s, uint32_t ms) {
    DWORD tv = (DWORD)(ms ? ms : GDB_DEF_TIMEOUT);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, (int)sizeof(tv));
}

static void gdb_set_timeouts(SOCKET s, uint32_t ms) {
    DWORD tv = (DWORD)(ms ? ms : GDB_DEF_TIMEOUT);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, (int)sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, (int)sizeof(tv));
}

static bool gdb_send_all(SOCKET s, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int chunk = (len - sent > 65536) ? 65536 : (int)(len - sent);
        int rc = send(s, buf + sent, chunk, 0);
        if (rc <= 0) return false;
        sent += (size_t)rc;
    }
    return true;
}

static bool gdb_recv_byte(SOCKET s, uint8_t *out) {
    int rc = recv(s, (char *)out, 1, 0);
    return rc == 1;
}

static void gdb_drop_sock(gdb_ctx *g) {
    if (g->sock != (uint64_t)INVALID_SOCKET && g->sock != 0)
        closesocket((SOCKET)g->sock);
    g->sock = (uint64_t)INVALID_SOCKET;
    g->connected = 0;
    g->no_ack = 0;
    g->port = 0;
    g->host[0] = 0;
    g->stop_sig[0] = 0;
    g->rip = 0;
    g->rflags = 0;
    memset(g->regs, 0, sizeof(g->regs));
}

static bool gdb_wait_connect(SOCKET s, uint32_t timeout_ms, int *err_out) {
    fd_set wfds;
    fd_set efds;
    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    wfds.fd_array[0] = s;
    wfds.fd_count = 1;
    efds.fd_array[0] = s;
    efds.fd_count = 1;

    struct timeval tv;
    tv.tv_sec = (long)(timeout_ms / 1000u);
    tv.tv_usec = (long)((timeout_ms % 1000u) * 1000u);

    int sel = select(0, NULL, &wfds, &efds, &tv);
    if (sel == 0) {
        *err_out = WSAETIMEDOUT;
        return false;
    }
    if (sel == SOCKET_ERROR) {
        *err_out = WSAGetLastError();
        return false;
    }
    int soerr = 0;
    int slen = (int)sizeof(soerr);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &slen) == SOCKET_ERROR) {
        *err_out = WSAGetLastError();
        return false;
    }
    if (soerr != 0 || FD_ISSET(s, &efds)) {
        *err_out = soerr ? soerr : WSAECONNREFUSED;
        return false;
    }
    return FD_ISSET(s, &wfds) != 0;
}

static SOCKET gdb_open_tcp(gdb_ctx *g, const char *host, uint16_t port, uint32_t timeout_ms) {
    char pstr[16];
    snprintf(pstr, sizeof(pstr), "%u", (unsigned)port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *res = NULL;
    int grc = getaddrinfo(host, pstr, &hints, &res);
    if (grc != 0 || !res) {
        gdb_err(g, "getaddrinfo failed", grc);
        return INVALID_SOCKET;
    }

    uint64_t deadline = GetTickCount64() + (uint64_t)timeout_ms;
    int last_werr = WSAECONNREFUSED;
    SOCKET out = INVALID_SOCKET;

    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        uint64_t now = GetTickCount64();
        if (now >= deadline) {
            last_werr = WSAETIMEDOUT;
            break;
        }
        uint32_t rem = (uint32_t)(deadline - now);

        SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) {
            last_werr = WSAGetLastError();
            continue;
        }

        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
        int rc = connect(s, ai->ai_addr, (int)ai->ai_addrlen);
        bool ok = (rc == 0);
        if (!ok) {
            int werr = WSAGetLastError();
            if (werr == WSAEWOULDBLOCK || werr == WSAEINPROGRESS)
                ok = gdb_wait_connect(s, rem, &last_werr);
            else
                last_werr = werr;
        }
        if (!ok) {
            closesocket(s);
            continue;
        }

        nb = 0;
        ioctlsocket(s, FIONBIO, &nb);
        int one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, (int)sizeof(one));
        gdb_set_timeouts(s, timeout_ms);
        out = s;
        break;
    }

    freeaddrinfo(res);
    if (out == INVALID_SOCKET) gdb_err(g, "connect failed", last_werr);
    return out;
}

static bool gdb_send_pkt(gdb_ctx *g, const char *payload, size_t len) {
    static const char hex[] = "0123456789abcdef";
    SOCKET s = (SOCKET)g->sock;

    char sbuf[1024];
    size_t need = len * 2 + 5;
    char *frame = (need <= sizeof(sbuf)) ? sbuf : (char *)malloc(need);
    if (!frame) {
        gdb_err(g, "out of memory", 0);
        return false;
    }

    size_t pos = 0;
    uint8_t csum = 0;
    frame[pos++] = '$';
    for (size_t i = 0; i < len; i++) {
        uint8_t b = (uint8_t)payload[i];
        if (b == '$' || b == '#' || b == '}' || b == '*') {
            frame[pos++] = '}';
            csum = (uint8_t)(csum + '}');
            b ^= 0x20u;
        }
        frame[pos++] = (char)b;
        csum = (uint8_t)(csum + b);
    }
    frame[pos++] = '#';
    frame[pos++] = hex[(csum >> 4) & 0xFu];
    frame[pos++] = hex[csum & 0xFu];

    bool ok = false;
    for (int tries = 0; tries < GDB_MAX_RETRY; tries++) {
        if (!gdb_send_all(s, frame, pos)) {
            gdb_err(g, "send failed", WSAGetLastError());
            break;
        }
        if (g->no_ack) {
            ok = true;
            break;
        }
        uint8_t ack = 0;
        if (!gdb_recv_byte(s, &ack)) {
            gdb_err(g, "ack recv failed", WSAGetLastError());
            break;
        }
        if (ack == '+') {
            ok = true;
            break;
        }
        if (ack != '-') {
            gdb_err(g, "unexpected ack byte", 0);
            break;
        }
    }

    if (frame != sbuf) free(frame);
    if (!ok && !g->last_err[0]) gdb_err(g, "packet nacked", 0);
    return ok;
}

static bool gdb_recv_pkt(gdb_ctx *g, char *out, size_t cap, size_t *out_len) {
    if (!out || cap == 0) return false;
    SOCKET s = (SOCKET)g->sock;

    for (int tries = 0; tries < GDB_MAX_RETRY; tries++) {
        uint8_t b = 0;
        bool found = false;
        for (int skip = 0; skip < 4096; skip++) {
            if (!gdb_recv_byte(s, &b)) {
                gdb_err(g, "recv failed", WSAGetLastError());
                return false;
            }
            if (b == '$') {
                found = true;
                break;
            }
        }
        if (!found) {
            gdb_err(g, "missing packet start", 0);
            return false;
        }

        uint8_t csum = 0;
        uint8_t last = 0;
        int has_last = 0;
        size_t len = 0;
        bool ended = false;

        for (size_t raw = 0; raw < 131072; raw++) {
            if (!gdb_recv_byte(s, &b)) {
                gdb_err(g, "recv failed", WSAGetLastError());
                return false;
            }
            if (b == '#') {
                ended = true;
                break;
            }
            // checksum covers raw wire bytes before escape or rle
            csum = (uint8_t)(csum + b);
            if (b == '}') {
                uint8_t esc = 0;
                if (!gdb_recv_byte(s, &esc)) {
                    gdb_err(g, "recv escape failed", WSAGetLastError());
                    return false;
                }
                csum = (uint8_t)(csum + esc);
                uint8_t dec = (uint8_t)(esc ^ 0x20u);
                if (len + 1 < cap) out[len++] = (char)dec;
                last = dec;
                has_last = 1;
            } else if (b == '*') {
                uint8_t rle = 0;
                if (!gdb_recv_byte(s, &rle)) {
                    gdb_err(g, "recv rle failed", WSAGetLastError());
                    return false;
                }
                csum = (uint8_t)(csum + rle);
                int rep = (int)rle - 29;
                if (has_last && rep > 0) {
                    for (int k = 0; k < rep; k++) {
                        if (len + 1 < cap) out[len++] = (char)last;
                    }
                }
            } else {
                if (len + 1 < cap) out[len++] = (char)b;
                last = b;
                has_last = 1;
            }
        }

        if (!ended) {
            gdb_err(g, "packet too long", 0);
            return false;
        }

        uint8_t h1 = 0, h2 = 0;
        if (!gdb_recv_byte(s, &h1) || !gdb_recv_byte(s, &h2)) {
            gdb_err(g, "recv checksum failed", WSAGetLastError());
            return false;
        }
        int hi = gdb_hex_val(h1);
        int lo = gdb_hex_val(h2);
        bool csum_ok = (hi >= 0 && lo >= 0 && (uint8_t)((hi << 4) | lo) == csum);
        if (csum_ok) {
            out[len] = 0;
            if (out_len) *out_len = len;
            if (!g->no_ack) gdb_send_all(s, "+", 1);
            return true;
        }
        if (g->no_ack) {
            gdb_err(g, "bad packet checksum", 0);
            return false;
        }
        gdb_send_all(s, "-", 1);
    }

    gdb_err(g, "checksum retry limit", 0);
    return false;
}

static bool gdb_xfer(gdb_ctx *g, const char *cmd, char *rep, size_t rep_cap, size_t *rep_len) {
    g->last_err[0] = 0;
    if (!gdb_send_pkt(g, cmd, strlen(cmd))) return false;
    return gdb_recv_pkt(g, rep, rep_cap, rep_len);
}

static bool gdb_recv_stop(gdb_ctx *g, char *rep, size_t rep_cap) {
    for (int i = 0; i < 64; i++) {
        size_t n = 0;
        if (!gdb_recv_pkt(g, rep, rep_cap, &n)) return false;
        // skip console output packets before actual stop reply
        if (n > 1 && rep[0] == 'O' && rep[1] != 'K') continue;
        return true;
    }
    gdb_err(g, "too many console packets", 0);
    return false;
}

static bool gdb_parse_le_hex(const char *s, size_t nbytes, uint64_t *out) {
    uint64_t v = 0;
    for (size_t i = 0; i < nbytes; i++) {
        int hi = gdb_hex_val((unsigned char)s[i * 2]);
        int lo = gdb_hex_val((unsigned char)s[i * 2 + 1]);
        uint8_t byte = 0;
        if (hi >= 0 && lo >= 0) {
            byte = (uint8_t)((hi << 4) | lo);
        } else if ((s[i * 2] == 'x' || s[i * 2] == 'X') &&
                   (s[i * 2 + 1] == 'x' || s[i * 2 + 1] == 'X')) {
            byte = 0;
        } else {
            return false;
        }
        v |= ((uint64_t)byte) << (i * 8);
    }
    *out = v;
    return true;
}

static bool gdb_is_err_reply(const char *rep, size_t len) {
    if (len == 3 && rep[0] == 'E' && gdb_hex_val((unsigned char)rep[1]) >= 0 &&
        gdb_hex_val((unsigned char)rep[2]) >= 0)
        return true;
    if (len >= 2 && rep[0] == 'E' && rep[1] == '.')
        return true;
    return false;
}

void gdb_init(gdb_ctx *g) {
    if (!g) return;
    memset(g, 0, sizeof(*g));
    g->sock = (uint64_t)INVALID_SOCKET;
}

void gdb_disconnect(gdb_ctx *g) {
    if (!g) return;
    if (g->connected && g->sock != (uint64_t)INVALID_SOCKET && g->sock != 0) {
        gdb_set_timeouts((SOCKET)g->sock, 200);
        gdb_send_pkt(g, "D", 1);
    }
    gdb_drop_sock(g);
    g->last_err[0] = 0;
}

bool gdb_connect(gdb_ctx *g, const char *host, uint16_t port, uint32_t timeout_ms) {
    if (!g) return false;
    if (!host || !host[0] || port == 0) {
        gdb_err(g, "invalid host or port", 0);
        return false;
    }

    gdb_disconnect(g);
    if (!gdb_wsa_init(g)) return false;

    uint32_t ms = timeout_ms ? timeout_ms : GDB_DEF_TIMEOUT;
    SOCKET s = gdb_open_tcp(g, host, port, ms);
    if (s == INVALID_SOCKET) return false;

    g->sock = (uint64_t)s;

    char rep[1024];
    if (!gdb_xfer(g, "qSupported:swbreak+;hwbreak+", rep, sizeof(rep), NULL)) {
        gdb_drop_sock(g);
        return false;
    }
    if (!gdb_xfer(g, "QStartNoAckMode", rep, sizeof(rep), NULL)) {
        gdb_drop_sock(g);
        return false;
    }
    if (strcmp(rep, "OK") == 0) g->no_ack = 1;

    if (!gdb_xfer(g, "?", rep, sizeof(rep), NULL)) {
        gdb_drop_sock(g);
        return false;
    }
    snprintf(g->stop_sig, sizeof(g->stop_sig), "%s", rep);

    g->connected = 1;
    snprintf(g->host, sizeof(g->host), "%s", host);
    g->port = port;
    g->last_err[0] = 0;

    gdb_read_regs(g);
    return true;
}

bool gdb_read_regs(gdb_ctx *g) {
    static const uint8_t gdb_to_canon[16] = {
        0, 3, 1, 2, 6, 7, 5, 4, 8, 9, 10, 11, 12, 13, 14, 15
    };
    if (!g || !g->connected) return false;

    char rep[4096];
    size_t len = 0;
    if (!gdb_xfer(g, "g", rep, sizeof(rep), &len)) return false;
    if (len < 17 * 16 || gdb_is_err_reply(rep, len)) {
        gdb_err(g, "bad register reply", 0);
        return false;
    }

    for (int i = 0; i < 16; i++) {
        uint64_t val = 0;
        if (!gdb_parse_le_hex(rep + (size_t)i * 16, 8, &val)) {
            gdb_err(g, "invalid register hex", 0);
            return false;
        }
        g->regs[gdb_to_canon[i]] = val;
    }
    if (!gdb_parse_le_hex(rep + 16 * 16, 8, &g->rip)) {
        gdb_err(g, "invalid rip hex", 0);
        return false;
    }
    if (len >= 17 * 16 + 8) {
        uint64_t ef = 0;
        if (gdb_parse_le_hex(rep + 17 * 16, 4, &ef)) g->rflags = ef;
    }
    return true;
}

bool gdb_step(gdb_ctx *g) {
    if (!g || !g->connected) return false;
    g->last_err[0] = 0;
    if (!gdb_send_pkt(g, "s", 1)) return false;

    char rep[256];
    if (!gdb_recv_stop(g, rep, sizeof(rep))) return false;
    snprintf(g->stop_sig, sizeof(g->stop_sig), "%s", rep);
    if (gdb_is_err_reply(rep, strlen(rep))) {
        gdb_err(g, rep, 0);
        return false;
    }
    if (rep[0] == 'W' || rep[0] == 'X') return true;
    return gdb_read_regs(g);
}

bool gdb_cont(gdb_ctx *g, uint32_t timeout_ms) {
    if (!g || !g->connected) return false;
    SOCKET s = (SOCKET)g->sock;
    g->last_err[0] = 0;

    gdb_set_rcv_timeout(s, timeout_ms ? timeout_ms : GDB_DEF_TIMEOUT);
    bool sent = gdb_send_pkt(g, "c", 1);
    char rep[256];
    bool ok = sent && gdb_recv_stop(g, rep, sizeof(rep));
    gdb_set_rcv_timeout(s, GDB_DEF_TIMEOUT);
    if (!ok) return false;

    snprintf(g->stop_sig, sizeof(g->stop_sig), "%s", rep);
    if (gdb_is_err_reply(rep, strlen(rep))) {
        gdb_err(g, rep, 0);
        return false;
    }
    if (rep[0] == 'W' || rep[0] == 'X') return true;
    return gdb_read_regs(g);
}

bool gdb_bp_add(gdb_ctx *g, uint64_t va, int hw) {
    if (!g || !g->connected) return false;
    char cmd[48], rep[64];
    snprintf(cmd, sizeof(cmd), "Z%d,%llx,1", hw ? 1 : 0, (unsigned long long)va);
    if (!gdb_xfer(g, cmd, rep, sizeof(rep), NULL)) return false;
    if (strcmp(rep, "OK") != 0) {
        gdb_err(g, rep[0] ? rep : "bp add unsupported", 0);
        return false;
    }
    return true;
}

bool gdb_bp_del(gdb_ctx *g, uint64_t va, int hw) {
    if (!g || !g->connected) return false;
    char cmd[48], rep[64];
    snprintf(cmd, sizeof(cmd), "z%d,%llx,1", hw ? 1 : 0, (unsigned long long)va);
    if (!gdb_xfer(g, cmd, rep, sizeof(rep), NULL)) return false;
    if (strcmp(rep, "OK") != 0) {
        gdb_err(g, rep[0] ? rep : "bp del unsupported", 0);
        return false;
    }
    return true;
}

size_t gdb_read_mem(gdb_ctx *g, uint64_t va, uint8_t *dst, size_t n) {
    if (!g || !g->connected || !dst || n == 0) return 0;

    size_t done = 0;
    char rep[GDB_MEM_CHUNK * 2 + 16];

    while (done < n) {
        size_t chunk = n - done;
        if (chunk > GDB_MEM_CHUNK) chunk = GDB_MEM_CHUNK;

        char cmd[48];
        snprintf(cmd, sizeof(cmd), "m%llx,%llx",
                 (unsigned long long)(va + (uint64_t)done), (unsigned long long)chunk);

        size_t rlen = 0;
        if (!gdb_xfer(g, cmd, rep, sizeof(rep), &rlen)) break;
        if (rlen == 0 || (rlen & 1u) != 0 || gdb_is_err_reply(rep, rlen)) break;

        size_t got = rlen / 2;
        if (got > chunk) got = chunk;
        size_t i = 0;
        for (; i < got; i++) {
            int hi = gdb_hex_val((unsigned char)rep[i * 2]);
            int lo = gdb_hex_val((unsigned char)rep[i * 2 + 1]);
            if (hi < 0 || lo < 0) break;
            dst[done + i] = (uint8_t)((hi << 4) | lo);
        }
        done += i;
        if (i < chunk) break;
    }
    return done;
}

bool gdb_write_mem(gdb_ctx *g, uint64_t va, const uint8_t *src, size_t n) {
    static const char hex[] = "0123456789abcdef";
    if (!g || !g->connected || !src || n == 0) return false;

    size_t done = 0;
    char cmd[64 + GDB_WR_CHUNK * 2];
    char rep[64];

    while (done < n) {
        size_t chunk = n - done;
        if (chunk > GDB_WR_CHUNK) chunk = GDB_WR_CHUNK;

        int hdr = snprintf(cmd, sizeof(cmd), "M%llx,%llx:",
                           (unsigned long long)(va + (uint64_t)done), (unsigned long long)chunk);
        if (hdr < 0 || (size_t)hdr + chunk * 2 + 1 > sizeof(cmd)) return false;

        char *p = cmd + hdr;
        for (size_t i = 0; i < chunk; i++) {
            uint8_t b = src[done + i];
            p[i * 2] = hex[(b >> 4) & 0xFu];
            p[i * 2 + 1] = hex[b & 0xFu];
        }
        p[chunk * 2] = 0;

        if (!gdb_xfer(g, cmd, rep, sizeof(rep), NULL)) return false;
        if (strcmp(rep, "OK") != 0) {
            gdb_err(g, rep[0] ? rep : "mem write failed", 0);
            return false;
        }
        done += chunk;
    }
    return true;
}
