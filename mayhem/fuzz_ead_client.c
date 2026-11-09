// libFuzzer harness for ead-client (package/network/services/ead/src/ead-client.c), the client of
// OpenWrt's Emergency Access Daemon. The client sends UDP broadcasts and handles whatever datagram
// answers on the socket, from any host on the segment, before authentication has completed.
//
// The input is one such datagram. Its first byte picks the request the client has just sent (ping,
// get-prime or send-A); the rest is delivered on the client's socket (a datagram socketpair stands in
// for the UDP socket) and the client's own receive loop, send_packet(), validates it and dispatches
// it to handle_pong(), handle_prime() or handle_b().
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#define main ead_client_main
#include "ead-client.c"
#undef main

static int peer = -1;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	int sv[2];

	(void)argc;
	(void)argv;
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
		return 1;
	s = sv[0];
	peer = sv[1];
	sockflags = fcntl(s, F_GETFL);
	/* answers are already queued on the socket: do not wait for more */
	timeout = 0;
	username = "root";
	/* handle_pong() prints the node list to stdout */
	if (freopen("/dev/null", "w", stdout) == NULL)
		return 1;
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 1)
		return -1;

	memset(msgbuf, 0, sizeof(msgbuf));
	memset(saltbuf, 0, sizeof(saltbuf));
	memset(bbuf, 0, sizeof(bbuf));
	memset(pw_salt, 0, sizeof(pw_salt));
	msg->magic = htonl(EAD_MAGIC);
	msg->sid = 0;
	nid = 0xffff;
	sid = 0;
	auth_type = EAD_AUTH_DEFAULT;
	B.len = 0;

	if (write(peer, data + 1, size - 1) != (ssize_t)(size - 1))
		return -1;

	switch (data[0] % 3) {
	case 0:
		send_ping();
		break;
	case 1:
		get_prime();
		break;
	default:
		msg->type = htonl(EAD_TYPE_SEND_A);
		msg->len = 0;
		send_packet(EAD_TYPE_SEND_B, handle_b, 1);
		break;
	}

	/* a datagram the client left unread must not leak into the next input */
	while (read(s, msgbuf, sizeof(msgbuf)) > 0)
		;
	if (tc) {
		t_clientclose(tc);
		tc = NULL;
	}
	return 0;
}
