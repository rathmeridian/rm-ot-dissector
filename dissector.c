/*
 * otdissect - passive OT/ICS network dissector
 * -------------------------------------------------------------------------
 * Reads a PCAP (or a live mirror/TAP feed) and produces a read-only asset
 * inventory, a communications map, an inferred Purdue-level model, and a
 * findings report (Markdown + a client-facing HTML page). It NEVER transmits:
 * the only thing it does on the wire is ask tshark to read packets.
 *
 * Pipeline (maps to the v0.1 -> v0.4 build phases):
 *   v0.1  ingest via tshark -T fields  ->  flow table -> flat asset list
 *   v0.2  per-protocol enrichment (Modbus / DNP3 / S7 / ENIP-CIP / BACnet)
 *   v0.3  comms graph (Graphviz .dot, auto-rendered) + Purdue inference
 *   v0.4  report generation (inventory.csv/.json, comms.dot/.png/.svg,
 *         report.md, report.html)
 *
 * Build:   gcc -O2 -Wall -o otdissect dissector.c
 * Runtime: requires `tshark` on PATH. Optional: graphviz `dot` for images.
 *
 * Author: Rath Meridian / Shawn Duffy
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

/* ----------------------------------------------------------------------- */
/* Limits                                                                   */
/* ----------------------------------------------------------------------- */
#define ASSET_CAP   8192
#define EDGE_CAP    65536
#define STR_IP      64
#define STR_MAC     64
#define STR_VEND    128
#define STR_PROD    128

/* ----------------------------------------------------------------------- */
/* Requested tshark fields. The enum indexes REQ[] (names). Output columns  */
/* are resolved dynamically after validation (see validate_fields), so the  */
/* enum order need NOT match tshark's output order.                         */
/* ----------------------------------------------------------------------- */
enum {
    F_TIME, F_ETH_SRC, F_ETH_DST, F_ETH_SRC_R, F_ETH_DST_R,
    F_IP_SRC, F_IP_DST, F_TCP_SP, F_TCP_DP, F_UDP_SP, F_UDP_DP,
    F_COL_PROTO, F_FRAME_PROTOS,
    F_MB_FUNC, F_MB_UNIT, F_MB_REF,
    F_DNP_FUNC, F_DNP_SRC, F_DNP_DST,
    F_S7_ROSCTR, F_S7_FUNC,
    F_ENIP_CMD, F_CIP_SC, F_ENIP_PROD, F_ENIP_VENDOR,
    F_BAC_TYPE, F_BAC_CONF, F_BAC_UNCONF, F_BAC_INST,
    NUM_FIELDS
};

static const char *REQ[NUM_FIELDS] = {
    "frame.time_epoch", "eth.src", "eth.dst", "eth.src_resolved", "eth.dst_resolved",
    "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "_ws.col.Protocol", "frame.protocols",
    "modbus.func_code", "mbtcp.unit_id", "modbus.reference_num",
    "dnp3.al.func", "dnp3.src", "dnp3.dst",
    "s7comm.header.rosctr", "s7comm.param.func",
    "enip.command", "cip.sc", "enip.lir.productname", "enip.lir.vendor",
    "bacapp.type", "bacapp.confirmed_service", "bacapp.unconfirmed_service",
    "bacapp.instance_number"
};

/* Resolved output column for each requested field, -1 if unavailable. */
static int col_of[NUM_FIELDS];
static int n_valid_cols = 0;

/* ----------------------------------------------------------------------- */
/* Protocol bitmask                                                         */
/* ----------------------------------------------------------------------- */
enum {
    P_MODBUS = 1 << 0,
    P_DNP3   = 1 << 1,
    P_S7     = 1 << 2,
    P_ENIP   = 1 << 3,
    P_BACNET = 1 << 4,
    P_OPCUA  = 1 << 5
};

static const char *proto_name(int bit) {
    switch (bit) {
        case P_MODBUS: return "Modbus/TCP";
        case P_DNP3:   return "DNP3";
        case P_S7:     return "S7comm";
        case P_ENIP:   return "EtherNet/IP";
        case P_BACNET: return "BACnet";
        case P_OPCUA:  return "OPC-UA";
        default:       return "?";
    }
}

/* Map a TCP/UDP port to a well-known OT protocol, else 0 (IT/other). */
static int classify_port(long port) {
    switch (port) {
        case 502:   return P_MODBUS;
        case 20000: return P_DNP3;
        case 102:   return P_S7;
        case 44818: return P_ENIP;   /* explicit messaging */
        case 2222:  return P_ENIP;   /* implicit I/O (UDP) */
        case 47808: return P_BACNET;
        case 4840:  return P_OPCUA;
        default:    return 0;
    }
}

/* ----------------------------------------------------------------------- */
/* Asset model                                                              */
/* ----------------------------------------------------------------------- */
typedef struct {
    char ip[STR_IP];
    char mac[STR_MAC];
    char vendor[STR_VEND];
    char product[STR_PROD];
    int  srv_mask;             /* OT protocols this host SERVES (listens)  */
    int  cli_mask;             /* OT protocols this host DRIVES (master)   */
    int  talks_it;
    int  talks_ot;
    int  level;                /* inferred Purdue level, -1 = unknown      */

    /* Modbus (attributed to the SERVER/PLC) */
    uint64_t mb_func[4];                 /* function codes 0..255 (incl 128+ exceptions) */
    long mb_ref_min, mb_ref_max;
    int  mb_units;

    /* DNP3 (attributed to the SERVER/outstation) */
    uint64_t dnp_func[4];                /* app-layer func codes 0..255 (incl 129/130) */
    long dnp_addr_min, dnp_addr_max;     /* logical addresses observed       */

    /* BACnet (attributed to the announcing/source device) */
    uint64_t bac_conf_mask;              /* confirmed services 0..63         */
    uint32_t bac_unconf_mask;            /* unconfirmed services 0..31       */
    long bac_instance;                   /* device instance (from I-Am)      */
    int  bac_seen;

    double first_seen, last_seen;
} Asset;

static Asset  assets[ASSET_CAP];
static int    asset_slot[ASSET_CAP];
static int    n_assets = 0;

/* ----------------------------------------------------------------------- */
/* Edge model                                                               */
/* ----------------------------------------------------------------------- */
typedef struct {
    int  src, dst, proto;
    unsigned long pkts;
} Edge;

static Edge   edges[EDGE_CAP];
static int    edge_slot[EDGE_CAP];
static int    n_edges = 0;

/* ----------------------------------------------------------------------- */
/* Helpers                                                                  */
/* ----------------------------------------------------------------------- */
static unsigned long djb2(const char *s) {
    unsigned long h = 5381; int c;
    while ((c = (unsigned char)*s++)) h = ((h << 5) + h) + c;
    return h;
}

static void safe_copy(char *dst, size_t cap, const char *src) {
    if (!src) { dst[0] = 0; return; }
    strncpy(dst, src, cap - 1);
    dst[cap - 1] = 0;
}

static long parse_long(const char *s) {
    if (!s || !*s) return -1;
    char *end;
    long v = strtol(s, &end, 0);
    if (end == s) return -1;
    return v;
}

static int vendor_from_resolved(const char *resolved, char *out, size_t cap) {
    if (!resolved || !*resolved) return 0;
    const char *us = strchr(resolved, '_');
    if (!us || us == resolved) return 0;
    size_t len = (size_t)(us - resolved);
    if (len >= cap) len = cap - 1;
    memcpy(out, resolved, len);
    out[len] = 0;
    return 1;
}

static void shell_quote(const char *in, char *out, size_t cap) {
    size_t o = 0;
    if (o < cap - 1) out[o++] = '\'';
    for (const char *p = in; *p && o < cap - 4; p++) {
        if (*p == '\'') { out[o++]='\''; out[o++]='\\'; out[o++]='\''; out[o++]='\''; }
        else out[o++] = *p;
    }
    if (o < cap - 1) out[o++] = '\'';
    out[o] = 0;
}

/* ----------------------------------------------------------------------- */
/* Field validation / column mapping                                        */
/* ----------------------------------------------------------------------- */
/* tshark -G fields emits one record per field:  F<TAB>descr<TAB>abbrev<...> */
static void validate_fields(void) {
    for (int i = 0; i < NUM_FIELDS; i++) col_of[i] = -1;
    int valid[NUM_FIELDS] = {0};

    FILE *p = popen("tshark -G fields 2>/dev/null", "r");
    int got = 0;
    if (p) {
        char *line = NULL; size_t cap = 0; ssize_t len;
        while ((len = getline(&line, &cap, p)) != -1) {
            if (line[0] != 'F' || line[1] != '\t') continue;
            /* abbrev is the 3rd tab-separated column */
            char *c1 = strchr(line, '\t');        if (!c1) continue;
            char *c2 = strchr(c1 + 1, '\t');      if (!c2) continue;
            char *c3 = strchr(c2 + 1, '\t');
            char *abbr = c2 + 1;
            if (c3) *c3 = 0; else { /* strip newline */
                size_t l = strlen(abbr);
                if (l && abbr[l-1] == '\n') abbr[l-1] = 0;
            }
            for (int f = 0; f < NUM_FIELDS; f++)
                if (!valid[f] && strcmp(REQ[f], abbr) == 0) { valid[f] = 1; got++; break; }
        }
        free(line);
        pclose(p);
    }

    /* If validation couldn't confirm the core fields (tshark missing, or the
     * -G output was unexpected), fall back to requesting everything and let
     * the main tshark call surface any error. */
    if (!valid[F_IP_SRC] || !valid[F_IP_DST] || got < 5) {
        for (int f = 0; f < NUM_FIELDS; f++) { valid[f] = 1; col_of[f] = f; }
        n_valid_cols = NUM_FIELDS;
        return;
    }
    int c = 0;
    for (int f = 0; f < NUM_FIELDS; f++)
        if (valid[f]) col_of[f] = c++;
    n_valid_cols = c;
}

/* Accessor: value of requested field f for the current packet's columns. */
static const char *G(char **cols, int f) {
    int c = col_of[f];
    return (c >= 0 && c < n_valid_cols) ? cols[c] : "";
}

/* ----------------------------------------------------------------------- */
/* Interning                                                                */
/* ----------------------------------------------------------------------- */
static int asset_index(const char *ip) {
    if (!ip || !*ip) return -1;
    unsigned long h = djb2(ip) % ASSET_CAP;
    for (int probe = 0; probe < ASSET_CAP; probe++) {
        int slot = (int)((h + probe) % ASSET_CAP);
        int idx = asset_slot[slot];
        if (idx == -1) {
            if (n_assets >= ASSET_CAP - 1) return -1;
            idx = n_assets++;
            memset(&assets[idx], 0, sizeof(Asset));
            safe_copy(assets[idx].ip, STR_IP, ip);
            assets[idx].level = -1;
            assets[idx].mb_ref_min = assets[idx].mb_ref_max = -1;
            assets[idx].dnp_addr_min = assets[idx].dnp_addr_max = -1;
            assets[idx].bac_instance = -1;
            assets[idx].first_seen = -1;
            asset_slot[slot] = idx;
            return idx;
        }
        if (strcmp(assets[idx].ip, ip) == 0) return idx;
    }
    return -1;
}

static int edge_index(int src, int dst, int proto) {
    char key[48];
    snprintf(key, sizeof key, "%d|%d|%d", src, dst, proto);
    unsigned long h = djb2(key) % EDGE_CAP;
    for (int probe = 0; probe < EDGE_CAP; probe++) {
        int slot = (int)((h + probe) % EDGE_CAP);
        int idx = edge_slot[slot];
        if (idx == -1) {
            if (n_edges >= EDGE_CAP - 1) return -1;
            idx = n_edges++;
            edges[idx].src = src; edges[idx].dst = dst;
            edges[idx].proto = proto; edges[idx].pkts = 0;
            edge_slot[slot] = idx;
            return idx;
        }
        if (edges[idx].src==src && edges[idx].dst==dst && edges[idx].proto==proto)
            return idx;
    }
    return -1;
}

/* ----------------------------------------------------------------------- */
/* Bit helpers                                                              */
/* ----------------------------------------------------------------------- */
/* 256-bit function-code set, so Modbus exception replies (128+) and DNP3
 * response/unsolicited codes (129/130) are preserved, not truncated. */
static void setbit256(uint64_t m[4], long f) {
    if (f < 0 || f >= 256) return;
    m[f >> 6] |= (1ULL << (f & 63));
}

static void list256(const uint64_t m[4], char *out, size_t cap) {
    out[0] = 0; char tmp[16]; int first = 1;
    for (int f = 0; f < 256; f++) if ((m[f >> 6] >> (f & 63)) & 1) {
        snprintf(tmp, sizeof tmp, "%s%d", first ? "" : ",", f);
        strncat(out, tmp, cap - strlen(out) - 1);
        first = 0;
    }
    if (first) safe_copy(out, cap, "-");
}

static void list_maskN(uint64_t m, int bits, char *out, size_t cap) {
    out[0] = 0; char tmp[16]; int first = 1;
    for (int f = 0; f < bits; f++) if ((m >> f) & 1) {
        snprintf(tmp, sizeof tmp, "%s%d", first ? "" : ",", f);
        strncat(out, tmp, cap - strlen(out) - 1);
        first = 0;
    }
    if (first) safe_copy(out, cap, "-");
}

/* ----------------------------------------------------------------------- */
/* Packet processing                                                        */
/* ----------------------------------------------------------------------- */
static void touch_asset(int idx, const char *mac, const char *resolved, double ts) {
    if (idx < 0) return;
    Asset *a = &assets[idx];
    if (!a->mac[0] && mac && *mac) safe_copy(a->mac, STR_MAC, mac);
    if (!a->vendor[0]) {
        char v[STR_VEND];
        if (vendor_from_resolved(resolved, v, sizeof v)) safe_copy(a->vendor, STR_VEND, v);
    }
    if (ts > 0) {
        if (a->first_seen < 0 || ts < a->first_seen) a->first_seen = ts;
        if (ts > a->last_seen) a->last_seen = ts;
    }
}

static void split_cols(char *line, char **cols, int ncols) {
    for (int i = 0; i < ncols; i++) cols[i] = "";
    int idx = 0; char *start = line;
    for (char *p = line; ; p++) {
        if (*p == '\t' || *p == '\0') {
            char c = *p; *p = 0;
            if (idx < ncols) cols[idx] = start;
            idx++; start = p + 1;
            if (c == '\0') break;
        }
    }
}

static void process_packet(char **cols) {
    const char *sip = G(cols, F_IP_SRC), *dip = G(cols, F_IP_DST);
    if (!*sip || !*dip) return;

    double ts = atof(G(cols, F_TIME));
    int si = asset_index(sip), di = asset_index(dip);
    if (si < 0 || di < 0) return;

    touch_asset(si, G(cols, F_ETH_SRC), G(cols, F_ETH_SRC_R), ts);
    touch_asset(di, G(cols, F_ETH_DST), G(cols, F_ETH_DST_R), ts);

    long sp = parse_long(G(cols, F_TCP_SP)), dp = parse_long(G(cols, F_TCP_DP));
    if (sp < 0) sp = parse_long(G(cols, F_UDP_SP));
    if (dp < 0) dp = parse_long(G(cols, F_UDP_DP));

    int proto = 0, server, client;
    int pd = classify_port(dp), ps = classify_port(sp);
    if (pd)      { proto = pd; server = di; client = si; }
    else if (ps) { proto = ps; server = si; client = di; }
    else         { proto = 0;  server = di; client = si; }

    if (proto) {
        assets[server].srv_mask |= proto;
        assets[client].cli_mask |= proto;
        assets[server].talks_ot = assets[client].talks_ot = 1;

        if (proto == P_MODBUS) {
            Asset *a = &assets[server];
            setbit256(a->mb_func, parse_long(G(cols, F_MB_FUNC)));
            long ref = parse_long(G(cols, F_MB_REF));
            if (ref >= 0) {
                if (a->mb_ref_min < 0 || ref < a->mb_ref_min) a->mb_ref_min = ref;
                if (ref > a->mb_ref_max) a->mb_ref_max = ref;
            }
            if (*G(cols, F_MB_UNIT)) a->mb_units = 1;
        } else if (proto == P_DNP3) {
            Asset *a = &assets[server];
            setbit256(a->dnp_func, parse_long(G(cols, F_DNP_FUNC)));
            long da = parse_long(G(cols, F_DNP_SRC));
            long db = parse_long(G(cols, F_DNP_DST));
            long addrs[2] = { da, db };
            for (int k = 0; k < 2; k++) {
                long v = addrs[k];
                if (v < 0) continue;
                if (a->dnp_addr_min < 0 || v < a->dnp_addr_min) a->dnp_addr_min = v;
                if (v > a->dnp_addr_max) a->dnp_addr_max = v;
            }
        } else if (proto == P_ENIP) {
            Asset *a = &assets[server];
            if (!a->product[0] && *G(cols, F_ENIP_PROD))
                safe_copy(a->product, STR_PROD, G(cols, F_ENIP_PROD));
        } else if (proto == P_BACNET) {
            /* BACnet is peer-to-peer; attribute identity to the source, which
             * is the device announcing itself (I-Am) or issuing the request. */
            Asset *a = &assets[si];
            a->bac_seen = 1;
            long cs = parse_long(G(cols, F_BAC_CONF));
            long us = parse_long(G(cols, F_BAC_UNCONF));
            if (cs >= 0 && cs < 64) a->bac_conf_mask   |= (1ULL << cs);
            if (us >= 0 && us < 32) a->bac_unconf_mask |= (1U  << us);
            long inst = parse_long(G(cols, F_BAC_INST));
            if (inst >= 0 && a->bac_instance < 0) a->bac_instance = inst;
        }
    } else {
        assets[si].talks_it = assets[di].talks_it = 1;
    }

    int e = edge_index(client, server, proto);
    if (e >= 0) edges[e].pkts++;
}

/* ----------------------------------------------------------------------- */
/* Inference                                                                */
/* ----------------------------------------------------------------------- */
static void infer_levels(void) {
    for (int i = 0; i < n_assets; i++) {
        Asset *a = &assets[i];
        int srv = a->srv_mask != 0, cli = a->cli_mask != 0;
        if (srv && !cli)      a->level = 1;
        else if (cli)         a->level = 2;
        else if (a->talks_it) a->level = 3;
        else                  a->level = -1;
    }
}

/* ----------------------------------------------------------------------- */
/* Shared formatting                                                        */
/* ----------------------------------------------------------------------- */
static void proto_list(int mask, char *out, size_t cap) {
    out[0] = 0;
    int bits[] = { P_MODBUS, P_DNP3, P_S7, P_ENIP, P_BACNET, P_OPCUA };
    int first = 1;
    for (int i = 0; i < 6; i++) if (mask & bits[i]) {
        if (!first) strncat(out, ", ", cap - strlen(out) - 1);
        strncat(out, proto_name(bits[i]), cap - strlen(out) - 1);
        first = 0;
    }
    if (first) safe_copy(out, cap, "-");
}

/* ----------------------------------------------------------------------- */
/* CSV / JSON                                                               */
/* ----------------------------------------------------------------------- */
static void write_csv(const char *dir) {
    char path[512]; snprintf(path, sizeof path, "%s/inventory.csv", dir);
    FILE *f = fopen(path, "w"); if (!f) return;
    fprintf(f, "ip,mac,vendor,product,purdue_level,serves,drives,talks_it\n");
    char srv[128], cli[128];
    for (int i = 0; i < n_assets; i++) {
        Asset *a = &assets[i];
        proto_list(a->srv_mask, srv, sizeof srv);
        proto_list(a->cli_mask, cli, sizeof cli);
        fprintf(f, "%s,%s,%s,%s,%d,\"%s\",\"%s\",%d\n",
                a->ip, a->mac, a->vendor, a->product, a->level, srv, cli, a->talks_it);
    }
    fclose(f);
}

static void json_escape(const char *s, FILE *f) {
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') { fputc('\\', f); fputc(*s, f); }
        else if ((unsigned char)*s < 0x20) fprintf(f, "\\u%04x", *s);
        else fputc(*s, f);
    }
}

static void write_json(const char *dir) {
    char path[512]; snprintf(path, sizeof path, "%s/inventory.json", dir);
    FILE *f = fopen(path, "w"); if (!f) return;
    char srv[128], cli[128], lst[512];
    fprintf(f, "{\n  \"assets\": [\n");
    for (int i = 0; i < n_assets; i++) {
        Asset *a = &assets[i];
        proto_list(a->srv_mask, srv, sizeof srv);
        proto_list(a->cli_mask, cli, sizeof cli);
        fprintf(f, "    {\n");
        fprintf(f, "      \"ip\": \"");      json_escape(a->ip, f);      fprintf(f, "\",\n");
        fprintf(f, "      \"mac\": \"");     json_escape(a->mac, f);     fprintf(f, "\",\n");
        fprintf(f, "      \"vendor\": \"");  json_escape(a->vendor, f);  fprintf(f, "\",\n");
        fprintf(f, "      \"product\": \""); json_escape(a->product, f); fprintf(f, "\",\n");
        fprintf(f, "      \"purdue_level\": %d,\n", a->level);
        fprintf(f, "      \"serves\": \"%s\",\n", srv);
        fprintf(f, "      \"drives\": \"%s\",\n", cli);
        fprintf(f, "      \"talks_it\": %s", a->talks_it ? "true" : "false");
        if (a->srv_mask & P_MODBUS) {
            list256(a->mb_func, lst, sizeof lst);
            fprintf(f, ",\n      \"modbus\": { \"func_codes\": \"%s\", "
                       "\"ref_min\": %ld, \"ref_max\": %ld }",
                    lst, a->mb_ref_min, a->mb_ref_max);
        }
        if (a->srv_mask & P_DNP3) {
            list256(a->dnp_func, lst, sizeof lst);
            fprintf(f, ",\n      \"dnp3\": { \"func_codes\": \"%s\", "
                       "\"addr_min\": %ld, \"addr_max\": %ld }",
                    lst, a->dnp_addr_min, a->dnp_addr_max);
        }
        if (a->bac_seen) {
            char cs[256], us[256];
            list_maskN(a->bac_conf_mask, 64, cs, sizeof cs);
            list_maskN(a->bac_unconf_mask, 32, us, sizeof us);
            fprintf(f, ",\n      \"bacnet\": { \"device_instance\": %ld, "
                       "\"confirmed_services\": \"%s\", \"unconfirmed_services\": \"%s\" }",
                    a->bac_instance, cs, us);
        }
        fprintf(f, ",\n      \"first_seen\": %.3f,\n", a->first_seen < 0 ? 0 : a->first_seen);
        fprintf(f, "      \"last_seen\": %.3f\n", a->last_seen);
        fprintf(f, "    }%s\n", (i == n_assets - 1) ? "" : ",");
    }
    fprintf(f, "  ]\n}\n");
    fclose(f);
}

/* ----------------------------------------------------------------------- */
/* Graphviz .dot + render                                                   */
/* ----------------------------------------------------------------------- */
static void write_dot(const char *dir) {
    char path[512]; snprintf(path, sizeof path, "%s/comms.dot", dir);
    FILE *f = fopen(path, "w"); if (!f) return;
    fprintf(f, "digraph ot {\n  rankdir=TB;\n  bgcolor=\"white\";\n"
               "  node [shape=box, fontname=\"Helvetica\", fontsize=10];\n"
               "  edge [fontname=\"Helvetica\", fontsize=8, color=\"#6b7280\"];\n");
    for (int i = 0; i < n_assets; i++) {
        Asset *a = &assets[i];
        const char *color = a->level==1 ? "#f8d7da" : a->level==2 ? "#d7e8ff" :
                            a->level==3 ? "#e9ecef" : "#ffffff";
        fprintf(f, "  \"%s\" [label=\"%s%s%s\\nL%d%s%s\", style=filled, fillcolor=\"%s\"];\n",
                a->ip, a->ip, a->vendor[0] ? "\\n" : "", a->vendor, a->level,
                a->product[0] ? "\\n" : "", a->product, color);
    }
    for (int i = 0; i < n_edges; i++) {
        Edge *e = &edges[i];
        fprintf(f, "  \"%s\" -> \"%s\" [label=\"%s (%lu)\", style=%s];\n",
                assets[e->src].ip, assets[e->dst].ip,
                e->proto ? proto_name(e->proto) : "IT", e->pkts,
                e->proto ? "solid" : "dashed");
    }
    fprintf(f, "}\n");
    fclose(f);
}

static void render_dot(const char *dir, int *have_png, int *have_svg) {
    *have_png = *have_svg = 0;
    if (system("command -v dot >/dev/null 2>&1") != 0) {
        fprintf(stderr, "[*] graphviz 'dot' not found - skipping image render "
                        "(comms.dot still written; run: dot -Tpng comms.dot -o comms.png)\n");
        return;
    }
    char dotp[600], outp[600], qdot[700], qout[700], cmd[1600];
    snprintf(dotp, sizeof dotp, "%s/comms.dot", dir);
    shell_quote(dotp, qdot, sizeof qdot);

    snprintf(outp, sizeof outp, "%s/comms.png", dir);
    shell_quote(outp, qout, sizeof qout);
    snprintf(cmd, sizeof cmd, "dot -Tpng %s -o %s 2>/dev/null", qdot, qout);
    if (system(cmd) == 0) *have_png = 1;

    snprintf(outp, sizeof outp, "%s/comms.svg", dir);
    shell_quote(outp, qout, sizeof qout);
    snprintf(cmd, sizeof cmd, "dot -Tsvg %s -o %s 2>/dev/null", qdot, qout);
    if (system(cmd) == 0) *have_svg = 1;

    if (*have_png) fprintf(stderr, "[*] rendered comms.png\n");
}

/* ----------------------------------------------------------------------- */
/* report.md                                                                */
/* ----------------------------------------------------------------------- */
static void write_report(const char *dir, const char *source) {
    char path[512]; snprintf(path, sizeof path, "%s/report.md", dir);
    FILE *f = fopen(path, "w"); if (!f) return;

    int l1=0,l2=0,l3=0,unk=0,pu=0;
    for (int i=0;i<n_assets;i++){
        switch(assets[i].level){case 1:l1++;break;case 2:l2++;break;
            case 3:l3++;break;default:unk++;}
        pu|=assets[i].srv_mask|assets[i].cli_mask;
    }
    char pul[128]; proto_list(pu, pul, sizeof pul);

    fprintf(f, "# OT Passive Assessment\n\n");
    fprintf(f, "**Source:** `%s`  \n**Method:** passive (read-only). "
               "No packets were transmitted.\n\n", source);
    fprintf(f, "## Summary\n\n| Metric | Value |\n|---|---|\n");
    fprintf(f, "| Hosts observed | %d |\n| Conversations | %d |\n", n_assets, n_edges);
    fprintf(f, "| OT protocols seen | %s |\n", pul);
    fprintf(f, "| L1 (controllers/field) | %d |\n| L2 (supervisory/HMI) | %d |\n", l1, l2);
    fprintf(f, "| L3 (enterprise/IT) | %d |\n| Unclassified | %d |\n\n", l3, unk);

    fprintf(f, "## Asset inventory\n\n| IP | Vendor | Device | Level | Serves | Drives |\n");
    fprintf(f, "|---|---|---|---|---|---|\n");
    char srv[128], cli[128];
    for (int i=0;i<n_assets;i++){
        Asset *a=&assets[i];
        proto_list(a->srv_mask,srv,sizeof srv);
        proto_list(a->cli_mask,cli,sizeof cli);
        fprintf(f, "| %s | %s | %s | L%d | %s | %s |\n", a->ip,
                a->vendor[0]?a->vendor:"-", a->product[0]?a->product:"-",
                a->level, srv, cli);
    }

    int any_mb=0, any_dnp=0, any_bac=0;
    for (int i=0;i<n_assets;i++){
        if (assets[i].srv_mask & P_MODBUS) any_mb=1;
        if (assets[i].srv_mask & P_DNP3)   any_dnp=1;
        if (assets[i].bac_seen)            any_bac=1;
    }
    char lst[512];
    if (any_mb) {
        fprintf(f, "\n## Modbus detail\n\n| Device | Function codes | Register range |\n|---|---|---|\n");
        for (int i=0;i<n_assets;i++){ Asset*a=&assets[i];
            if(!(a->srv_mask&P_MODBUS))continue;
            list256(a->mb_func, lst, sizeof lst);
            fprintf(f, "| %s | %s | %ld - %ld |\n", a->ip, lst, a->mb_ref_min, a->mb_ref_max);
        }
    }
    if (any_dnp) {
        fprintf(f, "\n## DNP3 detail\n\n| Outstation | App function codes | Logical addresses |\n|---|---|---|\n");
        for (int i=0;i<n_assets;i++){ Asset*a=&assets[i];
            if(!(a->srv_mask&P_DNP3))continue;
            list256(a->dnp_func, lst, sizeof lst);
            fprintf(f, "| %s | %s | %ld - %ld |\n", a->ip, lst, a->dnp_addr_min, a->dnp_addr_max);
        }
    }
    if (any_bac) {
        fprintf(f, "\n## BACnet detail\n\n| Device | Instance | Confirmed svc | Unconfirmed svc |\n|---|---|---|---|\n");
        for (int i=0;i<n_assets;i++){ Asset*a=&assets[i];
            if(!a->bac_seen)continue;
            char cs[256],us[256];
            list_maskN(a->bac_conf_mask, 64, cs, sizeof cs);
            list_maskN(a->bac_unconf_mask, 32, us, sizeof us);
            fprintf(f, "| %s | %ld | %s | %s |\n", a->ip, a->bac_instance, cs, us);
        }
    }

    fprintf(f, "\n## Findings\n\n");
    int findings=0;
    for (int i=0;i<n_assets;i++){ Asset*a=&assets[i];
        if (a->srv_mask && a->talks_it){
            fprintf(f, "- **Segmentation gap:** `%s` serves an OT protocol *and* appears "
                       "in IT/enterprise conversations. A Level 1/2 device reachable from "
                       "IT is a priority review item.\n", a->ip);
            findings++;
        }
        if (a->srv_mask && a->cli_mask &&
            __builtin_popcount(a->srv_mask|a->cli_mask) > 1){
            fprintf(f, "- **Protocol bridge:** `%s` both serves and drives OT protocols "
                       "across more than one family - confirm this is an intended "
                       "gateway/historian, not an unmanaged bridge.\n", a->ip);
            findings++;
        }
    }
    for (int i=0;i<n_edges;i++){ Edge*e=&edges[i];
        if(!e->proto)continue;
        int ls=assets[e->src].level, ld=assets[e->dst].level;
        if(ls>0&&ld>0&&(ls-ld>1||ld-ls>1)){
            fprintf(f, "- **Skip-level traffic:** `%s` (L%d) talks %s directly to `%s` (L%d), "
                       "crossing a Purdue boundary.\n",
                    assets[e->src].ip,ls,proto_name(e->proto),assets[e->dst].ip,ld);
            findings++;
        }
    }
    if(!findings)
        fprintf(f, "- No segmentation or boundary anomalies detected in this capture. "
                   "Absence of evidence is not evidence of absence - widen the capture "
                   "window and vantage points before concluding.\n");

    fprintf(f, "\n## Notes\n\n");
    fprintf(f, "- Purdue levels are *inferred* from traffic role and are a starting "
               "hypothesis, not ground truth. Validate against drawings and asset owners.\n");
    fprintf(f, "- Render the comms map: `dot -Tpng comms.dot -o comms.png`\n");
    fclose(f);
}

/* ----------------------------------------------------------------------- */
/* report.html (client-facing)                                              */
/* ----------------------------------------------------------------------- */
static void html_escape(const char *s, FILE *f) {
    for (; s && *s; s++) {
        switch (*s) {
            case '&': fputs("&amp;", f); break;
            case '<': fputs("&lt;", f);  break;
            case '>': fputs("&gt;", f);  break;
            case '"': fputs("&quot;", f);break;
            default:  fputc(*s, f);
        }
    }
}

/* Inline an SVG file's <svg>..</svg> into the open stream. Returns 1 on ok. */
static int inline_svg(const char *dir, FILE *out) {
    char path[512]; snprintf(path, sizeof path, "%s/comms.svg", dir);
    FILE *s = fopen(path, "r"); if (!s) return 0;
    fseek(s, 0, SEEK_END); long n = ftell(s); fseek(s, 0, SEEK_SET);
    if (n <= 0 || n > 50*1024*1024) { fclose(s); return 0; }
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(s); return 0; }
    size_t rd = fread(buf, 1, (size_t)n, s); buf[rd] = 0; fclose(s);
    char *svg = strstr(buf, "<svg");
    if (svg) fputs(svg, out);
    free(buf);
    return svg != NULL;
}

static void tile(FILE *f, const char *label, const char *value, const char *accent) {
    fprintf(f, "<div class=\"tile\"><div class=\"tval\" style=\"color:%s\">%s</div>"
               "<div class=\"tlbl\">%s</div></div>", accent, value, label);
}

static void write_html(const char *dir, const char *source, int have_svg) {
    char path[512]; snprintf(path, sizeof path, "%s/report.html", dir);
    FILE *f = fopen(path, "w"); if (!f) return;

    int l1=0,l2=0,l3=0,unk=0,pu=0,findings=0;
    for (int i=0;i<n_assets;i++){
        switch(assets[i].level){case 1:l1++;break;case 2:l2++;break;
            case 3:l3++;break;default:unk++;}
        pu|=assets[i].srv_mask|assets[i].cli_mask;
    }
    char pul[128]; proto_list(pu, pul, sizeof pul);
    char nb[32];

    fputs("<!doctype html>\n<html lang=\"en\"><head>\n<meta charset=\"utf-8\">\n"
          "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
          "<title>OT Passive Assessment</title>\n<style>\n"
          ":root{--ink:#1a1d21;--muted:#6b7280;--line:#e5e7eb;--bg:#ffffff;"
          "--accent:#0b5fff;--l1:#c0392b;--l2:#0b5fff;--l3:#6b7280;--hi:#fdecea;}\n"
          "*{box-sizing:border-box}body{margin:0;background:#f4f5f7;color:var(--ink);"
          "font:15px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;}\n"
          ".wrap{max-width:960px;margin:32px auto;background:var(--bg);border:1px solid var(--line);"
          "border-radius:12px;padding:32px 36px;}\n"
          "h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 12px;"
          "padding-bottom:6px;border-bottom:1px solid var(--line)}\n"
          ".sub{color:var(--muted);font-size:13px;margin:0 0 4px}\n"
          ".badge{display:inline-block;background:#e7f6ec;color:#1a7f3c;border:1px solid #bfe6cc;"
          "font-size:12px;font-weight:600;padding:2px 10px;border-radius:999px;margin-top:8px}\n"
          ".tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin:20px 0}\n"
          ".tile{border:1px solid var(--line);border-radius:10px;padding:14px 16px;background:#fafbfc}\n"
          ".tval{font-size:26px;font-weight:700;line-height:1}.tlbl{color:var(--muted);font-size:12px;margin-top:6px}\n"
          "table{width:100%;border-collapse:collapse;font-size:13.5px;margin-top:4px}\n"
          "th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}\n"
          "th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.03em}\n"
          "tr:last-child td{border-bottom:none}\n"
          ".pill{display:inline-block;font-size:11px;font-weight:600;padding:1px 8px;border-radius:999px}\n"
          ".l1{background:#f8d7da;color:#842029}.l2{background:#d7e8ff;color:#084298}"
          ".l3{background:#e9ecef;color:#41464b}.lx{background:#f1f3f5;color:#6b7280}\n"
          ".finding{border-left:3px solid var(--l1);background:var(--hi);padding:10px 14px;"
          "border-radius:0 8px 8px 0;margin:8px 0;font-size:13.5px}\n"
          ".ok{border-left:3px solid #1a7f3c;background:#e7f6ec;padding:10px 14px;border-radius:0 8px 8px 0}\n"
          ".map{border:1px solid var(--line);border-radius:10px;padding:12px;overflow:auto;background:#fff}\n"
          ".map svg{max-width:100%;height:auto}\n"
          "code{background:#f1f3f5;padding:1px 5px;border-radius:4px;font-size:12.5px}\n"
          "footer{color:var(--muted);font-size:12px;margin-top:28px;border-top:1px solid var(--line);padding-top:14px}\n"
          "</style></head><body><div class=\"wrap\">\n", f);

    fputs("<h1>OT Passive Assessment</h1>\n", f);
    fputs("<p class=\"sub\">Source: <code>", f); html_escape(source, f);
    fputs("</code></p>\n", f);
    fputs("<span class=\"badge\">READ-ONLY &middot; PASSIVE &middot; NO PACKETS TRANSMITTED</span>\n", f);

    fputs("<div class=\"tiles\">\n", f);
    snprintf(nb,sizeof nb,"%d",n_assets); tile(f,"Hosts",nb,"var(--ink)");
    snprintf(nb,sizeof nb,"%d",n_edges);  tile(f,"Conversations",nb,"var(--ink)");
    snprintf(nb,sizeof nb,"%d",l1);       tile(f,"L1 field/controller",nb,"var(--l1)");
    snprintf(nb,sizeof nb,"%d",l2);       tile(f,"L2 supervisory",nb,"var(--l2)");
    snprintf(nb,sizeof nb,"%d",l3);       tile(f,"L3 enterprise/IT",nb,"var(--l3)");
    fputs("</div>\n", f);
    fputs("<p class=\"sub\">OT protocols observed: <b>", f); html_escape(pul,f); fputs("</b></p>\n", f);

    /* Findings first - the part a client cares about */
    fputs("<h2>Findings</h2>\n", f);
    for (int i=0;i<n_assets;i++){ Asset*a=&assets[i];
        if (a->srv_mask && a->talks_it){
            fputs("<div class=\"finding\"><b>Segmentation gap:</b> <code>", f);
            html_escape(a->ip,f);
            fputs("</code> serves an OT protocol and also appears in IT/enterprise "
                  "traffic. A Level 1/2 device reachable from IT is a priority review item.</div>\n", f);
            findings++;
        }
        if (a->srv_mask && a->cli_mask && __builtin_popcount(a->srv_mask|a->cli_mask)>1){
            fputs("<div class=\"finding\"><b>Protocol bridge:</b> <code>", f);
            html_escape(a->ip,f);
            fputs("</code> both serves and drives OT protocols across more than one "
                  "family. Confirm this is an intended gateway/historian.</div>\n", f);
            findings++;
        }
    }
    for (int i=0;i<n_edges;i++){ Edge*e=&edges[i];
        if(!e->proto)continue;
        int ls=assets[e->src].level, ld=assets[e->dst].level;
        if(ls>0&&ld>0&&(ls-ld>1||ld-ls>1)){
            fprintf(f,"<div class=\"finding\"><b>Skip-level traffic:</b> <code>%s</code> (L%d) "
                      "talks %s directly to <code>%s</code> (L%d), crossing a Purdue boundary.</div>\n",
                    assets[e->src].ip,ls,proto_name(e->proto),assets[e->dst].ip,ld);
            findings++;
        }
    }
    if(!findings)
        fputs("<div class=\"ok\">No segmentation or boundary anomalies detected in this "
              "capture. Absence of evidence is not evidence of absence - widen the capture "
              "window and vantage points before concluding.</div>\n", f);

    /* Comms map */
    fputs("<h2>Communications map</h2>\n", f);
    if (have_svg) { fputs("<div class=\"map\">\n", f); inline_svg(dir, f); fputs("</div>\n", f); }
    else fputs("<p class=\"sub\">Install graphviz and run "
               "<code>dot -Tsvg comms.dot -o comms.svg</code> to embed the map.</p>\n", f);

    /* Inventory */
    fputs("<h2>Asset inventory</h2>\n<table><thead><tr>"
          "<th>IP</th><th>Vendor</th><th>Device</th><th>Level</th>"
          "<th>Serves</th><th>Drives</th></tr></thead><tbody>\n", f);
    char srv[128], cli[128];
    for (int i=0;i<n_assets;i++){ Asset*a=&assets[i];
        proto_list(a->srv_mask,srv,sizeof srv);
        proto_list(a->cli_mask,cli,sizeof cli);
        const char *pc = a->level==1?"l1":a->level==2?"l2":a->level==3?"l3":"lx";
        fputs("<tr><td><code>", f); html_escape(a->ip,f); fputs("</code></td><td>", f);
        html_escape(a->vendor[0]?a->vendor:"-",f); fputs("</td><td>", f);
        html_escape(a->product[0]?a->product:"-",f);
        fprintf(f, "</td><td><span class=\"pill %s\">L%d</span></td><td>", pc, a->level);
        html_escape(srv,f); fputs("</td><td>", f); html_escape(cli,f);
        fputs("</td></tr>\n", f);
    }
    fputs("</tbody></table>\n", f);

    /* Protocol detail */
    char lst[512];
    int any_mb=0,any_dnp=0,any_bac=0;
    for(int i=0;i<n_assets;i++){
        if(assets[i].srv_mask&P_MODBUS) any_mb=1;
        if(assets[i].srv_mask&P_DNP3)   any_dnp=1;
        if(assets[i].bac_seen)          any_bac=1;
    }

    if (any_mb){
        fputs("<h2>Modbus detail</h2>\n<table><thead><tr><th>Device</th>"
              "<th>Function codes</th><th>Register range</th></tr></thead><tbody>\n", f);
        for(int i=0;i<n_assets;i++){ Asset*a=&assets[i]; if(!(a->srv_mask&P_MODBUS))continue;
            list256(a->mb_func, lst, sizeof lst);
            fprintf(f,"<tr><td><code>%s</code></td><td>%s</td><td>%ld - %ld</td></tr>\n",
                    a->ip,lst,a->mb_ref_min,a->mb_ref_max);
        }
        fputs("</tbody></table>\n", f);
    }
    if (any_dnp){
        fputs("<h2>DNP3 detail</h2>\n<table><thead><tr><th>Outstation</th>"
              "<th>App function codes</th><th>Logical addresses</th></tr></thead><tbody>\n", f);
        for(int i=0;i<n_assets;i++){ Asset*a=&assets[i]; if(!(a->srv_mask&P_DNP3))continue;
            list256(a->dnp_func, lst, sizeof lst);
            fprintf(f,"<tr><td><code>%s</code></td><td>%s</td><td>%ld - %ld</td></tr>\n",
                    a->ip,lst,a->dnp_addr_min,a->dnp_addr_max);
        }
        fputs("</tbody></table>\n", f);
    }
    if (any_bac){
        fputs("<h2>BACnet detail</h2>\n<table><thead><tr><th>Device</th><th>Instance</th>"
              "<th>Confirmed svc</th><th>Unconfirmed svc</th></tr></thead><tbody>\n", f);
        for(int i=0;i<n_assets;i++){ Asset*a=&assets[i]; if(!a->bac_seen)continue;
            char cs[256],us[256];
            list_maskN(a->bac_conf_mask, 64, cs, sizeof cs);
            list_maskN(a->bac_unconf_mask, 32, us, sizeof us);
            fprintf(f,"<tr><td><code>%s</code></td><td>%ld</td><td>%s</td><td>%s</td></tr>\n",
                    a->ip,a->bac_instance,cs,us);
        }
        fputs("</tbody></table>\n", f);
    }

    fputs("<footer>Purdue levels are inferred from traffic role (who listens vs. who "
          "drives) and are a starting hypothesis, not ground truth &mdash; validate against "
          "drawings and asset owners. Generated by otdissect (passive, read-only).</footer>\n", f);
    fputs("</div></body></html>\n", f);
    fclose(f);
}

/* ----------------------------------------------------------------------- */
/* tshark invocation                                                        */
/* ----------------------------------------------------------------------- */
static FILE *open_tshark(int live, const char *target, int duration) {
    char cmd[8192]; char q[2048];
    shell_quote(target, q, sizeof q);
    size_t n = 0;
    n += snprintf(cmd+n, sizeof cmd-n, "tshark ");
    if (live) n += snprintf(cmd+n, sizeof cmd-n, "-i %s -a duration:%d ", q, duration);
    else      n += snprintf(cmd+n, sizeof cmd-n, "-r %s ", q);
    n += snprintf(cmd+n, sizeof cmd-n, "-n -N m -T fields -E separator=/t -E occurrence=f ");
    for (int f = 0; f < NUM_FIELDS; f++)
        if (col_of[f] >= 0) n += snprintf(cmd+n, sizeof cmd-n, "-e %s ", REQ[f]);
    n += snprintf(cmd+n, sizeof cmd-n, "2>/dev/null");
    return popen(cmd, "r");
}

/* ----------------------------------------------------------------------- */
/* main                                                                     */
/* ----------------------------------------------------------------------- */
static void usage(const char *p) {
    fprintf(stderr,
        "otdissect - passive OT/ICS dissector (read-only)\n\n"
        "  %s -r <capture.pcap> [-o outdir]\n"
        "  %s -i <iface> [-d seconds] [-o outdir]\n\n"
        "Requires tshark on PATH. Optional graphviz 'dot' for the comms image.\n"
        "Never transmits.\n", p, p);
}

int main(int argc, char **argv) {
    const char *pcap=NULL,*iface=NULL,*outdir="."; int duration=60;
    for (int i=1;i<argc;i++){
        if(!strcmp(argv[i],"-r")&&i+1<argc)pcap=argv[++i];
        else if(!strcmp(argv[i],"-i")&&i+1<argc)iface=argv[++i];
        else if(!strcmp(argv[i],"-o")&&i+1<argc)outdir=argv[++i];
        else if(!strcmp(argv[i],"-d")&&i+1<argc)duration=atoi(argv[++i]);
        else { usage(argv[0]); return 1; }
    }
    if(!pcap&&!iface){ usage(argv[0]); return 1; }

    for(int i=0;i<ASSET_CAP;i++)asset_slot[i]=-1;
    for(int i=0;i<EDGE_CAP;i++)edge_slot[i]=-1;

    validate_fields();

    const char *source = pcap ? pcap : iface;
    fprintf(stderr,"[*] otdissect: passive read of %s (no packets will be sent)\n", source);

    FILE *in = open_tshark(iface!=NULL, source, duration);
    if(!in){ fprintf(stderr,"[!] could not start tshark (is it installed?)\n"); return 2; }

    char *line=NULL; size_t cap=0; ssize_t len; unsigned long pkts=0;
    char **cols = malloc(sizeof(char*) * (n_valid_cols>0?n_valid_cols:1));
    if(!cols){ pclose(in); return 3; }
    while((len=getline(&line,&cap,in))!=-1){
        if(len && line[len-1]=='\n') line[len-1]=0;
        split_cols(line, cols, n_valid_cols);
        process_packet(cols);
        pkts++;
    }
    free(line); free(cols);
    int rc=pclose(in);
    if(rc!=0) fprintf(stderr,"[!] tshark exited non-zero - check the capture/interface.\n");

    infer_levels();

    write_csv(outdir);
    write_json(outdir);
    write_dot(outdir);
    int have_png=0, have_svg=0;
    render_dot(outdir, &have_png, &have_svg);
    write_report(outdir, source);
    write_html(outdir, source, have_svg);

    fprintf(stderr,
        "[*] %lu packets parsed -> %d hosts, %d conversations\n"
        "[*] wrote inventory.csv, inventory.json, comms.dot%s%s, report.md, report.html to %s/\n",
        pkts, n_assets, n_edges,
        have_png?", comms.png":"", have_svg?", comms.svg":"", outdir);
    return 0;
}
