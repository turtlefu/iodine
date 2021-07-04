#include "ecdh.h"


#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "encoding.h"

#ifdef HAVE_MONOCYPHER
#include <monocypher.h>
#endif /* HAVE_MONOCYPHER */

void
debug_hex(const char *const desc, const void *const buf, size_t buflen)
{
	fprintf(stdout, "%s: %p: %zd:", desc, buf, buflen);
	for(int i = 0; i<buflen; i++){
		fprintf(stdout, " %02x", *(((uint8_t *)buf)+i));
	}
	fprintf(stdout, "\n");
}

int
ec_arg_decode_pubkey(uint8_t *outkey, const char * const inkey)
{
	if (44 != strlen(inkey)) {
		return 1;
	}
	char buf[32+1] = "";
	size_t consumed = sizeof(buf)-1;
	size_t decoded = base64_ops.decode(buf, &consumed,
	    inkey, strlen(inkey));
	if (32 != decoded) {
		fprintf(stdout, "fuck decode\n");
		return 1;
	}
	memcpy(outkey, buf, 32);
	return 0;
}

int
ec_server_parse_arg(char *optarg, ec_server_config_t *config)
{
#ifndef HAVE_MONOCYPHER
	return 1;
#else
	/* 32 == sizeof(elliptic_key)
	   44 = (32 * 4) / 3 + (32*4) % 3
	   base64 of 32 bytes: 44 including padding '='
	*/
	if (44 != strlen(optarg)) {
		return 1;
	}
	char b64_tmp[44+1] = { -1 };
	size_t consumed = sizeof(config->eddsa_secret);
	size_t decoded = base64_ops.decode(b64_tmp, &consumed,
	    optarg, strlen(optarg));
	crypto_wipe(optarg, strlen(optarg));
	if (decoded != sizeof(config->eddsa_secret)) {
		return 55;
	}
	memcpy(config->eddsa_secret, b64_tmp, sizeof(config->eddsa_secret));
	crypto_wipe(b64_tmp, sizeof(b64_tmp));
	optarg[0] = 0;
	const unsigned char * hello = (unsigned char *)"hello";
	crypto_sign_public_key(config->eddsa_public, config->eddsa_secret);
	uint8_t signature[64] = {0};
	crypto_sign(signature, config->eddsa_secret, config->eddsa_public, hello, 5);
	if (crypto_check(signature, config->eddsa_public, hello, 5)) {
		return 12;
	}

	consumed = sizeof(b64_tmp) - 1;
	decoded = base64_ops.encode(b64_tmp, &consumed,
	    config->eddsa_public, sizeof(config->eddsa_public));
	if (43 != decoded || consumed != sizeof(config->eddsa_public)) {
		/* decoded should be 43, 44 with padding '=' */
		return 25;
	}
	b64_tmp[decoded] = '=';
	b64_tmp[decoded+1] = 0;
	uint8_t check[32] = "";
	if (ec_arg_decode_pubkey(check, b64_tmp)
		|| memcmp(check, config->eddsa_public, sizeof(check))) {
		return 23;
	}
	fprintf(stdout, "EC server public key: %zd %zd %s\n",
	    consumed, decoded, b64_tmp);
	crypto_wipe(b64_tmp, sizeof(b64_tmp));
	return 0;
#endif /* HAVE_MONOCYPHER */
}

int
ec_client_start_session(ec_session_t *session,
    ec_msg_client_hello_t *msg, ec_keys_t *ec_keys)
{
#ifndef HAVE_MONOCYPHER
	return 1;
#else /* HAVE_MONOCYPHER */
	if (getentropy(session->own_secret, sizeof(session->own_secret))) {
		return 1;
	}
	crypto_x25519_public_key(msg->client_pub, session->own_secret);
	ec_keys->ec_state = EC_CLIENT_HELLO;
	return 0;
#endif /* HAVE_MONOCYPHER */
}

int
ec_client_parse_response(ec_session_t *session,
    const e_response_msg_t *const resp,
    const ec_msg_client_hello_t *const client_hello,
    const uint8_t *const ec_server_pubkey, ec_keys_t *ec_keys)
{
#ifndef HAVE_MONOCYPHER
	return 1;
#else /* HAVE_MONOCYPHER */
	e_response_signed_t expected = {0};
	memcpy(expected.server_pub, resp->server_pub, sizeof(expected.server_pub));
	memcpy(&expected.client_hello, client_hello, sizeof(expected.client_hello));
	if (crypto_check(resp->signature, ec_server_pubkey,
		(uint8_t *)&expected, sizeof(expected))) {
		return 2;
	}

	crypto_key_exchange(session->shared_secret, session->own_secret,
	    expected.server_pub);
	if (ec_derive_keys(ec_keys, session->shared_secret, expected.server_pub)) {
		return 3;
	}
	return 0;
#endif
}

int
ec_server_start_session(char *const unpacked,
    const ec_server_config_t config,
    e_response_msg_t *e_response,
    ec_session_t *ec_session, ec_keys_t *ec_keys)
{
#ifndef HAVE_MONOCYPHER
	return 1;
#else /* HAVE_MONOCYPHER */
	uint8_t own_secret[32] = { 0 };
	e_response_signed_t e_response_signed = { 0 };

	// get user's x25519 key
	fprintf(stdout, "EC userid %d\n", unpacked[0]);
	e_response_signed.client_hello = *((ec_msg_client_hello_t *)unpacked);
	if (getentropy(own_secret, sizeof(own_secret))) {
		return 1;
	}
	crypto_x25519_public_key(e_response_signed.server_pub,
	    own_secret);
	memcpy(e_response->server_pub, e_response_signed.server_pub,
	    sizeof(e_response->server_pub));
	crypto_key_exchange(ec_session->shared_secret,
	    own_secret,
	    e_response_signed.client_hello.client_pub);
	if (ec_derive_keys(ec_keys, ec_session->shared_secret, e_response_signed.server_pub)){
		return 1;
	}
	crypto_sign(e_response->signature,
	    config.eddsa_secret, config.eddsa_public,
	    (const uint8_t *)&e_response_signed, sizeof(e_response_signed));

	return 0;
#endif
}

int
ec_encrypt(uint8_t *plain, size_t *plain_len,
    const uint8_t (*const key))
{
#ifndef HAVE_MONOCYPHER
	return -1;
#else
	uint8_t nonce[24] = {0};
	if (*plain_len >= 64*1024-16) {
		return -1;
	}
	crypto_lock(plain+*plain_len, /* mac */
	    plain, (uint8_t *)key,
	    nonce, plain, *plain_len);
	fprintf(stdout, "ec_encrypt plain_len %zd key:%x mac:%x\n",
	    *plain_len, *key, *(plain+*plain_len));
	*plain_len += 16;
	debug_hex("ec_e", plain, *plain_len);
	return 0;
#endif /* HAVE_MONOCYPHER */
}

int
ec_decrypt(uint8_t *plain, size_t *plain_len,
    const uint8_t *const key)
{
#ifndef HAVE_MONOCYPHER
	return -1;
#else
	uint8_t nonce[24] = {0};
	uint8_t mac[16] = {0};
	debug_hex("ec_d", plain, *plain_len);
	*plain_len = *plain_len - 16;
	if (*plain_len >= 64*1024-sizeof(mac)) {
		fprintf(stdout, "ec_decrypt wrong plain_len %zd / %zd\n",
		    *plain_len, *plain_len+16);
		return -1;
	}
	fprintf(stdout, "ec_decrypt plain_len %zd key:%x mac:%x\n",
	    *plain_len, *key, *(plain+*plain_len));
	if (crypto_unlock(plain, (uint8_t *)key,
		nonce,
		plain+*plain_len, /* mac */
		plain, *plain_len)) {
		return -1;
	}
	return 0;
#endif /* HAVE_MONOCYPHER */
}

int
ec_derive_keys(ec_keys_t *ec_keys, const uint8_t *const shared_secret,
    const uint8_t *const server_pub)
{
	/* Hash in the server's public signing key.
	   This is not sent over the wire, so this acts as a basic preventative
	   measure to prevent clients that do not know the public key from
	   connecting. */
	uint8_t tmp_shared_secret[64] = {0};
	memcpy(tmp_shared_secret, shared_secret, 32);
	memcpy(tmp_shared_secret+32, server_pub, 32);

	debug_hex("shared", tmp_shared_secret, sizeof(tmp_shared_secret));
	crypto_blake2b_general(ec_keys->ec_server_send_key,
	    sizeof(ec_keys->ec_server_send_key),
	    (uint8_t *)tmp_shared_secret, sizeof(tmp_shared_secret),
	    (uint8_t *)"server", 6);
	debug_hex("serverkey", ec_keys->ec_server_send_key, sizeof(ec_keys->ec_server_send_key));
	crypto_blake2b_general(ec_keys->ec_client_send_key,
	    sizeof(ec_keys->ec_client_send_key),
	    (uint8_t *)tmp_shared_secret, sizeof(tmp_shared_secret),
	    (uint8_t *)"client", 6);
	debug_hex("clientkey", ec_keys->ec_client_send_key, sizeof(ec_keys->ec_client_send_key));
	crypto_wipe(tmp_shared_secret, sizeof(tmp_shared_secret));
	ec_keys->ec_state = EC_ESTABLISHED;
	return 0;
}
