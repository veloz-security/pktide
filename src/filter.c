#include "core.h"

enum { F_TRUE, F_AND, F_OR, F_NOT, F_IP, F_PROTO, F_ARP, F_PORT, F_HOST, F_VLAN };
struct parser { struct filter *f; const char *pos; char token[80]; unsigned depth; };

static void next(struct parser *p)
{
    unsigned n = 0;
    while (*p->pos == ' ' || *p->pos == '\t' || *p->pos == '\n') p->pos++;
    if (*p->pos == '(' || *p->pos == ')') p->token[n++] = *p->pos++;
    else {
        while (*p->pos && *p->pos != '(' && *p->pos != ')' &&
               *p->pos != ' ' && *p->pos != '\t' && *p->pos != '\n') {
            if (n + 1 < sizeof(p->token)) p->token[n++] = *p->pos;
            else p->f->error = "filter token is too long";
            p->pos++;
        }
    }
    p->token[n] = 0;
}
static int is(struct parser *p, const char *s) { return pt_streq(p->token, s); }
static int node(struct parser *p, int kind, int left, int right)
{
    int id;
    if (p->f->error) return -1;
    if (p->f->count == PT_FILTER_NODES) {
        p->f->error = "filter exceeds 128 nodes"; return -1;
    }
    id = p->f->count++;
    p->f->nodes[id].kind = kind;
    p->f->nodes[id].left = left; p->f->nodes[id].right = right;
    return id;
}
static int expression(struct parser *p);
static int primary(struct parser *p)
{
    int id = -1, direction = 0, kind = -1, ipver = 0;
    u32 value = 0;
    if (p->f->error) return -1;
    if (++p->depth > 32) { p->f->error = "filter nesting exceeds 32"; goto done; }
    if (is(p, "not") || is(p, "!")) {
        int child;
        next(p); child = primary(p); id = node(p, F_NOT, child, -1); goto done;
    }
    if (is(p, "(")) {
        next(p); id = expression(p);
        if (!is(p, ")")) p->f->error = "missing ')' in filter";
        else next(p);
        goto done;
    }
    if (is(p, "src") || is(p, "dst")) {
        direction = is(p, "src") ? 1 : 2; next(p);
        if (!is(p, "host") && !is(p, "port")) {
            p->f->error = "src/dst requires host or port"; goto done;
        }
    }
    if (is(p, "host")) kind = F_HOST;
    else if (is(p, "port")) kind = F_PORT;
    else if (is(p, "vlan")) kind = F_VLAN;
    else if (is(p, "arp")) kind = F_ARP;
    else if (is(p, "ip")) { kind = F_IP; ipver = 4; }
    else if (is(p, "ip6")) { kind = F_IP; ipver = 6; }
    else if (is(p, "tcp")) { kind = F_PROTO; value = 6; }
    else if (is(p, "udp")) { kind = F_PROTO; value = 17; }
    else if (is(p, "icmp")) { kind = F_PROTO; value = 1; ipver = 4; }
    else if (is(p, "icmp6")) { kind = F_PROTO; value = 58; ipver = 6; }
    else { p->f->error = "unknown filter term (see --help)"; goto done; }
    id = node(p, kind, -1, -1);
    if (id < 0) goto done;
    p->f->nodes[id].direction = direction;
    p->f->nodes[id].ipver = ipver;
    p->f->nodes[id].value = value;
    next(p);
    if (kind == F_PORT) {
        if (!pt_uint(p->token, 65535, &p->f->nodes[id].value)) {
            p->f->error = "port must be a number from 0 to 65535"; goto done;
        }
        next(p);
    } else if (kind == F_HOST) {
        p->f->nodes[id].ipver = pt_address(p->token, p->f->nodes[id].address);
        if (!p->f->nodes[id].ipver) { p->f->error = "host requires a numeric IPv4/IPv6 address"; goto done; }
        next(p);
    }
done:
    p->depth--;
    return id;
}

static int conjunction(struct parser *p)
{
    int left = primary(p);
    while (!p->f->error && *p->token && !is(p, ")") && !is(p, "or") && !is(p, "||")) {
        int right;
        if (is(p, "and") || is(p, "&&")) next(p);
        right = primary(p); left = node(p, F_AND, left, right);
    }
    return left;
}
static int expression(struct parser *p)
{
    int left = conjunction(p);
    while (!p->f->error && (is(p, "or") || is(p, "||"))) {
        int right;
        next(p); right = conjunction(p); left = node(p, F_OR, left, right);
    }
    return left;
}
int filter_parse(struct filter *f, const char *expression_text)
{
    struct parser p;
    pt_memset(f, 0, sizeof(*f)); pt_memset(&p, 0, sizeof(p));
    p.f = f; p.pos = expression_text; next(&p);
    if (!*p.token) f->root = node(&p, F_TRUE, -1, -1);
    else {
        f->root = expression(&p);
        if (*p.token && !f->error) f->error = "unexpected token in filter";
    }
    return f->error == 0;
}
static int match(const struct filter *f, int id, const struct packet *p)
{
    const struct filter_node *n;
    int a, b;
    if (id < 0 || id >= f->count) return 0;
    n = &f->nodes[id];
    switch (n->kind) {
    case F_TRUE: return 1;
    case F_AND: return match(f, n->left, p) && match(f, n->right, p);
    case F_OR: return match(f, n->left, p) || match(f, n->right, p);
    case F_NOT: return !match(f, n->left, p);
    case F_IP: return !p->arp && p->ipver == n->ipver;
    case F_PROTO: return !p->arp && p->ipver && p->protocol == n->value &&
                         (!n->ipver || p->ipver == n->ipver);
    case F_ARP: return p->arp;
    case F_VLAN: return p->vlan;
    case F_PORT:
        if (!p->ports) return 0;
        a = p->sport == n->value; b = p->dport == n->value; break;
    case F_HOST:
        if (p->ipver != n->ipver) return 0;
        a = pt_equal(p->src, n->address, p->ipver == 4 ? 4 : 16);
        b = pt_equal(p->dst, n->address, p->ipver == 4 ? 4 : 16); break;
    default: return 0;
    }
    return n->direction == 1 ? a : n->direction == 2 ? b : a || b;
}
int filter_match(const struct filter *f, const struct packet *p)
{
    return f->error ? 0 : match(f, f->root, p);
}
