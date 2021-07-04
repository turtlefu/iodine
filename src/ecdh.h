#ifndef __ECDH_H__
#define __ECDH_H__

#include <stdint.h>
#include <stddef.h>

/* state structs: */

typedef struct {
	uint8_t eddsa_secret[32];
	uint8_t eddsa_public[32];
} ec_server_config_t;

typedef enum {
	EC_NONE      = 1,
	EC_WAIT      = 2,
	EC_SERVER    = 4,
	EC_CLIENT    = 8,
} ec_session_state_t;

typedef struct {
	uint8_t shared_secret[32];
	uint8_t own_secret[32];
	uint8_t peer_public[32];
	ec_session_state_t state;
} ec_session_t;

typedef struct {
	uint8_t ec_client_send_key[32];
	uint8_t ec_server_send_key[32];
	ec_session_state_t ec_state;
} ec_keys_t;

/* message structs */

typedef struct {
	uint8_t userid;
	uint8_t client_pub[32];
} __attribute((packed)) ec_msg_client_hello_t;

typedef struct {
	ec_msg_client_hello_t client_hello;
	uint8_t server_pub[32];
} __attribute__((packed)) e_response_signed_t;


typedef struct {
	uint8_t server_pub[32];
	uint8_t signature[64];
} __attribute__((packed)) e_response_msg_t;

/* Common functions */

void debug_hex(const char *const _description, const void *const _buf, size_t _buf_len);

int
ec_arg_decode_pubkey(uint8_t *_outbuf, const char * const _inbuf);

int
ec_encrypt(uint8_t *_plain, size_t *_plain_len, const ec_keys_t *const _keys);

int
ec_decrypt(uint8_t *_plain, size_t *_plain_len, const ec_keys_t (*const _keys));

int
ec_derive_keys(ec_keys_t *_ec_keys, const uint8_t *const _shared_secret,
    const uint8_t *const _server_public_key, int is_server);

/* Client functions */

int
ec_client_start_session(ec_session_t *_session, ec_msg_client_hello_t *_msg, ec_keys_t *_ec_keys);

int
ec_client_parse_response(ec_session_t *_session,
    const e_response_msg_t *const _resp,
    const ec_msg_client_hello_t *const _hello,
    const uint8_t *const _ec_server_pubkey,
    ec_keys_t *_ec_keys);

/* Server functions */


/*
 * Parse the -e cmdline argument for the server and derive signing keys.
 */
int
ec_server_parse_arg(char *_optarg, ec_server_config_t *_config);

/*
 * Reply to a request from client to establish ECDH session with server.
 * Returns 0 on success.
 */
int
ec_server_start_session(char * const _unpacked,
    ec_server_config_t _config,
    e_response_msg_t *_e_response,
    ec_session_t *_ec_session, ec_keys_t *_ec_keys);

#endif /* __ECDH_H__ */
