// Known-answer test for ead-client's reply handlers (package/network/services/ead/src/ead-client.c),
// built with the project's normal flags. Each reply is delivered on the client's socket (a datagram
// socketpair) and goes through the client's own receive loop, as a network reply would.
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#define main ead_client_main
#include "ead-client.c"
#undef main

static int peer;

static void deliver(uint32_t type, uint16_t nidv, const void *body, size_t len)
{
	unsigned char pkt[sizeof(msgbuf)];
	struct ead_msg *m = (struct ead_msg *)pkt;

	memset(pkt, 0, sizeof(pkt));
	m->magic = htonl(EAD_MAGIC);
	m->len = htonl(len);
	m->type = htonl(type);
	m->nid = htons(nidv);
	m->sid = htons(0x0042);
	memcpy(pkt + sizeof(*m), body, len);
	if (write(peer, pkt, sizeof(*m) + len) < 0)
		perror("write");
}

static void hex(const char *label, const unsigned char *p, int n)
{
	int i;

	printf("%s=", label);
	for (i = 0; i < n; i++)
		printf("%02x", p[i]);
	printf("\n");
}

int main(void)
{
	int sv[2];
	unsigned char body[256];
	struct ead_msg_pong *pong = (struct ead_msg_pong *)body;
	struct ead_msg_salt *sb = (struct ead_msg_salt *)body;
	struct ead_msg_number *num = (struct ead_msg_number *)body;
	int n, i;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
		return 1;
	s = sv[0];
	peer = sv[1];
	sockflags = fcntl(s, F_GETFL);
	timeout = 0;
	username = "root";
	msg->magic = htonl(EAD_MAGIC);

	/* ping -> pong naming the node */
	memset(body, 0, sizeof(body));
	pong->auth_type = htons(EAD_AUTH_MD5);
	memcpy(pong->name, "openwrt-ap", 10);
	deliver(EAD_TYPE_PONG, 0x1a2b, body, sizeof(struct ead_msg_pong) + 10);
	n = send_ping();
	fflush(stdout);
	printf("pong handled=%d auth_type=%d sid=%04x\n", n, auth_type, ntohs(sid));

	/* get-prime -> prime: parameter set 0 with a 16 byte salt */
	memset(body, 0, sizeof(body));
	sb->prime = 0;
	sb->len = 16;
	for (i = 0; i < 16; i++)
		sb->salt[i] = 0xa0 + i;
	for (i = 0; i < MAXSALTLEN; i++)
		sb->ext_salt[i] = 'a' + (i % 26);
	deliver(EAD_TYPE_PRIME, 0x1a2b, body, sizeof(struct ead_msg_salt));
	n = get_prime();
	printf("prime handled=%d tc=%d salt_len=%d modulus_len=%d\n", n, tc != NULL, salt.len, tcp->modulus.len);
	hex("salt", salt.data, salt.len);
	printf("pw_salt=%s\n", pw_salt);

	/* send-A -> B: a 20 byte number */
	memset(body, 0, sizeof(body));
	num->id = 1;
	for (i = 0; i < 20; i++)
		num->data[i] = 0x10 + 3 * i;
	deliver(EAD_TYPE_SEND_B, 0x1a2b, body, sizeof(struct ead_msg_number) + 20);
	msg->type = htonl(EAD_TYPE_SEND_A);
	msg->len = 0;
	n = send_packet(EAD_TYPE_SEND_B, handle_b, 1);
	printf("b handled=%d B_len=%d\n", n, B.len);
	hex("B", B.data, B.len);

	return 0;
}
