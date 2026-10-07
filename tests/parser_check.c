#include "core.h"
#include <stdio.h>
#include <stdlib.h>

static u32 random_state = 0xace51234U;
static u32 random32(void)
{
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return random_state;
}

int main(void)
{
    u8 data[512], addr[16];
    struct packet p;
    struct filter f;
    struct text t = {{0}, 0};
    unsigned trial, i;
    const char *expressions[] = {"", "tcp port 443", "ip or ip6", "not (udp or arp)",
                                "src host ::ffff:192.0.2.1", "vlan and dst port 0"};
    text_num(&t, ~(u64)0, 0);
    if (t.len != 20 || !pt_equal(t.data, "18446744073709551615", 20)) abort();
    if (pt_address("::ffff:192.0.2.1", addr) != 6 || addr[10] != 255 || addr[15] != 1) abort();
    for (trial = 0; trial < 100000; trial++) {
        u32 cap = random32() % (u32)sizeof(data);
        u32 wire = cap + random32() % 100;
        u32 links[] = {PT_ETHERNET, PT_LINUX_SLL, PT_RAW_IP, PT_NULL, PT_LOOP};
        const char *expression = expressions[trial % (sizeof(expressions) / sizeof(expressions[0]))];
        for (i = 0; i < sizeof(data); i++) data[i] = (u8)random32();
        if (trial % 3 == 0) { data[12] = 8; data[13] = 0; data[14] = 0x45; }
        if (trial % 3 == 1) { data[12] = 0x86; data[13] = 0xdd; data[14] = 0x60; }
        if (!filter_parse(&f, expression)) abort();
        packet_decode(&p, data, cap, wire, links[trial % 5]);
        (void)filter_match(&f, &p);
        t.len = 0; packet_summary(&t, &p);
        if (t.len >= sizeof(t.data)) abort();
    }
    for (trial = 0; trial < 10000; trial++) {
        char expression[200];
        unsigned len = random32() % (unsigned)(sizeof(expression) - 1);
        for (i = 0; i < len; i++) expression[i] = "tcp udoiransf()!012: ."[random32() % 21];
        expression[len] = 0;
        if (filter_parse(&f, expression)) (void)filter_match(&f, &p);
    }
    puts("PASS: 100,000 bounded packet inputs, 10,000 filter inputs, integer/address checks");
    return 0;
}
