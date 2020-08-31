#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "sk-api.h"
#include "webauthn/webauthn.h"
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif //HAVE_CONFIG_H

typedef DWORD (*TWebAuthNGetApiVersionNumber)();
typedef HRESULT (*TWebAuthNIsUserVerifyingPlatformAuthenticatorAvailable)(BOOL *);
typedef HRESULT (*TWebAuthNAuthenticatorMakeCredential)(HWND, PCWEBAUTHN_RP_ENTITY_INFORMATION, PCWEBAUTHN_USER_ENTITY_INFORMATION, PCWEBAUTHN_COSE_CREDENTIAL_PARAMETERS, PCWEBAUTHN_CLIENT_DATA, PCWEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS, PWEBAUTHN_CREDENTIAL_ATTESTATION *);
typedef HRESULT (*TWebAuthNAuthenticatorGetAssertion)(HWND, LPCWSTR, PCWEBAUTHN_CLIENT_DATA, PCWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS, PWEBAUTHN_ASSERTION *);
typedef void (*TWebAuthNFreeCredentialAttestation)(PWEBAUTHN_CREDENTIAL_ATTESTATION);
typedef void (*TWebAuthNFreeAssertion)(PWEBAUTHN_ASSERTION);
typedef PCWSTR (*TWebAuthNGetErrorName)(HRESULT);

static HMODULE winHelloLib = NULL;
static TWebAuthNGetApiVersionNumber webAuthNGetApiVersionNumber;
static TWebAuthNIsUserVerifyingPlatformAuthenticatorAvailable webAuthNIsUserVerifyingPlatformAuthenticatorAvailable;
static TWebAuthNAuthenticatorMakeCredential webAuthNAuthenticatorMakeCredential;
static TWebAuthNAuthenticatorGetAssertion webAuthNAuthenticatorGetAssertion;
static TWebAuthNFreeCredentialAttestation webAuthNFreeCredentialAttestation;
static TWebAuthNFreeAssertion webAuthNFreeAssertion;
static TWebAuthNGetErrorName webAuthNGetErrorName;

static void skdebug(const char *func, const char *fmt, ...)
{
#if defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#else
	(void)func; /* XXX */
	(void)fmt;	/* XXX */
#endif
}

/* Return the version of the middleware API */
uint32_t sk_api_version(void)
{
	return SSH_SK_VERSION_MAJOR;
}

static int init_winhello()
{
	static int loaded = 0;
	if (loaded)
		return 0;
	winHelloLib = LoadLibrary("webauthn.dll");
	if (!winHelloLib)
	{
		skdebug(__func__, "webauthn.dll could not be loaded (Are you using Win 10 v1903 or higher?)");
		return -1;
	}
	webAuthNGetApiVersionNumber = (TWebAuthNGetApiVersionNumber)GetProcAddress(winHelloLib, "WebAuthNGetApiVersionNumber");
	webAuthNIsUserVerifyingPlatformAuthenticatorAvailable = (TWebAuthNIsUserVerifyingPlatformAuthenticatorAvailable)GetProcAddress(winHelloLib, "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable");
	webAuthNAuthenticatorMakeCredential = (TWebAuthNAuthenticatorMakeCredential)GetProcAddress(winHelloLib, "WebAuthNAuthenticatorMakeCredential");
	webAuthNAuthenticatorGetAssertion = (TWebAuthNAuthenticatorGetAssertion)GetProcAddress(winHelloLib, "WebAuthNAuthenticatorGetAssertion");
	webAuthNFreeCredentialAttestation = (TWebAuthNFreeCredentialAttestation)GetProcAddress(winHelloLib, "WebAuthNFreeCredentialAttestation");
	webAuthNFreeAssertion = (TWebAuthNFreeAssertion)GetProcAddress(winHelloLib, "WebAuthNFreeAssertion");
	webAuthNGetErrorName = (TWebAuthNGetErrorName)GetProcAddress(winHelloLib, "WebAuthNGetErrorName");
	if (!webAuthNGetApiVersionNumber || !webAuthNIsUserVerifyingPlatformAuthenticatorAvailable || !webAuthNAuthenticatorMakeCredential || !webAuthNAuthenticatorGetAssertion || !webAuthNFreeCredentialAttestation || !webAuthNFreeAssertion || !webAuthNGetErrorName)
	{
		skdebug(__func__, "Cannot load functions from dll");
		return -1;
	}
	BOOL user = 0;
	int isUserAvailable = webAuthNIsUserVerifyingPlatformAuthenticatorAvailable(&user);
	if (webAuthNGetApiVersionNumber() < 1)
	{
		skdebug(__func__, "WinHello version should be 1+.\nCurrent version is: %u", webAuthNGetApiVersionNumber());
		return -1;
	}
	if (isUserAvailable == 0 && user == 1)
	{
		loaded = 1;
		return 0;
	}
	skdebug(__func__, "WARNING! This should not be like this!\nWinHello API Error: Version=%u, Is user available=%d, user=%d", webAuthNGetApiVersionNumber(), isUserAvailable, user);
	return 0;
}

static int convert_byte_string(const char *oneByte, size_t size, wchar_t *twoByte)
{
	return swprintf(twoByte, size, L"%hs", oneByte);
}

static int check_enroll_options(struct sk_option **options, uint8_t *user_id, size_t user_id_len)
{
	if (options == NULL)
		return 0;
	for (size_t i = 0; options[i] != NULL; i++)
	{
		if (strcmp(options[i]->name, "device") == 0)
		{
			skdebug(__func__, "requested device %s(Not needed in WinHello API)", options[i]->value);
		}
		else if (strcmp(options[i]->name, "user") == 0)
		{
			if (strlcpy(user_id, options[i]->value, user_id_len) >= user_id_len)
			{
				skdebug(__func__, "user too long");
				return -1;
			}
			skdebug(__func__, "requested user %s", (char *)user_id);
		}
		else
		{
			skdebug(__func__, "requested unsupported option %s", options[i]->name);
			if (options[i]->required)
			{
				skdebug(__func__, "unknown required option");
				return -1;
			}
		}
	}
	return 0;
}

static int pack_public_key_ecdsa(PBYTE cred, struct sk_enroll_response *response)
{
	BIGNUM *x = NULL, *y = NULL;
	EC_POINT *q = NULL;
	EC_GROUP *g = NULL;
	int ret = -1;

	response->public_key = NULL;
	response->public_key_len = 0;

	if ((x = BN_new()) == NULL || (y = BN_new()) == NULL || (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == NULL || (q = EC_POINT_new(g)) == NULL)
	{
		skdebug(__func__, "libcrypto setup failed");
		goto out;
	}
	if (BN_bin2bn(cred + 10, 32, x) == NULL || BN_bin2bn(cred + 10 + 32 + 3, 32, y) == NULL)
	{
		skdebug(__func__, "BN_bin2bn failed");
		goto out;
	}
	if (EC_POINT_set_affine_coordinates_GFp(g, q, x, y, NULL) != 1)
	{
		skdebug(__func__, "EC_POINT_set_affine_coordinates_GFp failed");
		goto out;
	}
	response->public_key_len = EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	if (response->public_key_len == 0 || response->public_key_len > 2048)
	{
		skdebug(__func__, "bad pubkey length %zu",
				response->public_key_len);
		goto out;
	}
	if ((response->public_key = malloc(response->public_key_len)) == NULL)
	{
		skdebug(__func__, "malloc pubkey failed");
		goto out;
	}
	if (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED, response->public_key, response->public_key_len, NULL) == 0)
	{
		skdebug(__func__, "EC_POINT_point2oct failed");
		goto out;
	}
	ret = 0;
out:
	if (ret != 0 && response->public_key != NULL)
	{
		memset(response->public_key, 0, response->public_key_len);
		free(response->public_key);
		response->public_key = NULL;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	return ret;
}

static int pack_public_key_ed25519(PBYTE cred, struct sk_enroll_response *response)
{
	if ((response->public_key = calloc(1, 32)) == NULL)
	{
		skdebug(__func__, "calloc public_key failed");
		return -1;
	}
	response->public_key_len = 32;
	memcpy(response->public_key, cred + 10, 32);
	return 0;
}

static int pack_public_key(uint32_t alg, PBYTE cred, struct sk_enroll_response *response)
{
	switch (alg)
	{
	case SSH_SK_ECDSA:
		return pack_public_key_ecdsa(cred, response);
		break;
	case SSH_SK_ED25519:
		return pack_public_key_ed25519(cred, response);
	default:
		return -1;
	}
}

/* Enroll a U2F key (private key generation) */
int sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len, const char *application, uint8_t flags, const char *pin, struct sk_option **options, struct sk_enroll_response **enroll_response)
{
	uint8_t user_id[32];
	int cose_alg = 0;
	struct sk_enroll_response *response = NULL;
	int ret = SSH_SK_ERR_GENERAL;

	if (enroll_response == NULL)
	{
		skdebug(__func__, "enroll_response == NULL");
		return SSH_SK_ERR_GENERAL;
	}
	*enroll_response = NULL;

	memset(user_id, 0, sizeof(user_id));
	if (check_enroll_options(options, user_id, sizeof(user_id)) != 0)
		return SSH_SK_ERR_GENERAL;

	switch (alg)
	{
	case SSH_SK_ECDSA:
		cose_alg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;
		break;
	case SSH_SK_ED25519:
		cose_alg = -8; //Not on header but it's working.
		break;
	default:
		skdebug(__func__, "unsupported key type %d", alg);
		return SSH_SK_ERR_UNSUPPORTED;
	}

	if (!(flags & SSH_SK_USER_PRESENCE_REQD))
	{
		skdebug(__func__, "WinHello API does not support no-touch-required");
		return SSH_SK_ERR_UNSUPPORTED;
	}

	if (init_winhello() != 0)
		return SSH_SK_ERR_UNSUPPORTED;

	WEBAUTHN_CREDENTIAL_ATTESTATION *pWebAuthNCredentialAttestation = NULL;

	size_t application_len = strlen(application) + 1;
	wchar_t *lApplication = (wchar_t *)calloc(application_len, sizeof(wchar_t));
	if (lApplication == NULL)
	{
		skdebug(__func__, "calloc lApplication failed");
		goto out;
	}
	if (convert_byte_string(application, application_len, lApplication) <= 0)
	{
		skdebug(__func__, "convert_string application failed");
		goto out;
	}
	//maybe use application in friendly name?
	WEBAUTHN_RP_ENTITY_INFORMATION rpInfo = {WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION, lApplication, L"SSH", NULL};

	//TODO: check user_id and email being required, check name in resident
	WEBAUTHN_USER_ENTITY_INFORMATION userInfo = {WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION, strlen(user_id) + 1, user_id, user_id, NULL, L"Name"};

	WEBAUTHN_COSE_CREDENTIAL_PARAMETER coseParam = {WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, cose_alg};
	WEBAUTHN_COSE_CREDENTIAL_PARAMETERS WebAuthNCredentialParameters = {1, &coseParam};

	WEBAUTHN_CLIENT_DATA WebAuthNClientData = {WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, challenge_len, (uint8_t *)challenge, WEBAUTHN_HASH_ALGORITHM_SHA_256};

	WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS WebAuthNCredentialOptions = {WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION, 60000, {0, NULL}, {0, NULL}, WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY, flags & SSH_SK_RESIDENT_KEY, WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED, WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY, 0, NULL, NULL};

	HWND hWnd = GetForegroundWindow();

	HRESULT hr = webAuthNAuthenticatorMakeCredential(hWnd, &rpInfo, &userInfo, &WebAuthNCredentialParameters, &WebAuthNClientData, &WebAuthNCredentialOptions, &pWebAuthNCredentialAttestation);
	if (hr != S_OK)
	{
		skdebug(__func__, "WinHello API Error %d:%ls", hr, webAuthNGetErrorName(hr));
		goto out;
	}

	size_t keyOffset = 32 + 1 + 4 + 16 + 2 + pWebAuthNCredentialAttestation->cbCredentialId;
	if ((alg == SSH_SK_ECDSA && pWebAuthNCredentialAttestation->cbAuthenticatorData < keyOffset + 10 + 32 + 3 + 32) ||
		(alg == SSH_SK_ED25519 && pWebAuthNCredentialAttestation->cbAuthenticatorData < keyOffset + 10 + 32))
	{
		skdebug(__func__, "Invalid response format");
		goto out;
	}

	if ((response = calloc(1, sizeof(*response))) == NULL)
	{
		skdebug(__func__, "calloc response failed");
		goto out;
	}

	if ((response->key_handle = calloc(1, pWebAuthNCredentialAttestation->cbCredentialId)) == NULL)
	{
		skdebug(__func__, "calloc key_handle failed");
		goto out;
	}
	response->key_handle_len = pWebAuthNCredentialAttestation->cbCredentialId;
	memcpy(response->key_handle, pWebAuthNCredentialAttestation->pbCredentialId, pWebAuthNCredentialAttestation->cbCredentialId);

	if (pack_public_key(alg, pWebAuthNCredentialAttestation->pbAuthenticatorData + keyOffset, response) != 0)
	{
		skdebug(__func__, "pack_public_key failed");
		goto out;
	}

	if (pWebAuthNCredentialAttestation->dwAttestationDecodeType == WEBAUTHN_ATTESTATION_DECODE_COMMON)
	{
		PWEBAUTHN_COMMON_ATTESTATION att = (PWEBAUTHN_COMMON_ATTESTATION)pWebAuthNCredentialAttestation->pvAttestationDecode;
		if (att->cX5c > 0)
		{
			if ((response->attestation_cert = calloc(1, att->pX5c[0].cbData)) == NULL)
			{
				skdebug(__func__, "calloc attestation_cert failed");
				goto out;
			}
			response->attestation_cert_len = att->pX5c[0].cbData;
			memcpy(response->attestation_cert, att->pX5c[0].pbData, att->pX5c[0].cbData);

			if ((response->signature = calloc(1, att->cbSignature)) == NULL)
			{
				skdebug(__func__, "calloc attestation_cert failed");
				goto out;
			}
			response->signature_len = att->cbSignature;
			memcpy(response->signature, att->pbSignature, att->cbSignature);
		}
	}
	*enroll_response = response;
	response = NULL;
	ret = 0;
out:
	webAuthNFreeCredentialAttestation(pWebAuthNCredentialAttestation);
	free(lApplication);
	if (response != NULL)
	{
		free(response->key_handle);
		free(response->public_key);
		free(response->attestation_cert);
		free(response->signature);
		free(response);
	}
	return ret;
}

static int check_sign_load_resident_options(struct sk_option **options)
{
	if (options == NULL)
		return 0;
	for (size_t i = 0; options[i] != NULL; i++)
	{
		if (strcmp(options[i]->name, "device") == 0)
		{
			skdebug(__func__, "requested device %s(Not needed in WinHello API)", options[i]->value);
		}
		else
		{
			skdebug(__func__, "requested unsupported option %s", options[i]->name);
			if (options[i]->required)
			{
				skdebug(__func__, "unknown required option");
				return -1;
			}
		}
	}
	return 0;
}

static int pack_sig_ecdsa(const BYTE *sign, size_t len, struct sk_sign_response *response)
{
	ECDSA_SIG *sig = NULL;
	const BIGNUM *sig_r, *sig_s;
	int ret = -1;

	if ((sig = d2i_ECDSA_SIG(NULL, &sign, len)) == NULL)
	{
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		goto out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_num_bytes(sig_r);
	response->sig_s_len = BN_num_bytes(sig_s);
	if ((response->sig_r = calloc(1, response->sig_r_len)) == NULL || (response->sig_s = calloc(1, response->sig_s_len)) == NULL)
	{
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
out:
	ECDSA_SIG_free(sig);
	if (ret != 0)
	{
		free(response->sig_r);
		free(response->sig_s);
		response->sig_r = NULL;
		response->sig_s = NULL;
	}
	return ret;
}

static int pack_sig_ed25519(BYTE *sign, size_t len, struct sk_sign_response *response)
{
	int ret = -1;

	if (len != 64)
	{
		skdebug(__func__, "bad length %zu", len);
		goto out;
	}
	response->sig_r_len = len;
	if ((response->sig_r = calloc(1, response->sig_r_len)) == NULL)
	{
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	memcpy(response->sig_r, sign, len);
	ret = 0;
out:
	if (ret != 0)
	{
		free(response->sig_r);
		response->sig_r = NULL;
	}
	return ret;
}

static int pack_sig(uint32_t alg, BYTE *sign, size_t len, struct sk_sign_response *response)
{
	switch (alg)
	{
	case SSH_SK_ECDSA:
		return pack_sig_ecdsa(sign, len, response);
	case SSH_SK_ED25519:
		return pack_sig_ed25519(sign, len, response);
	default:
		return -1;
	}
}

/* Sign a challenge */
int sk_sign(uint32_t alg, const uint8_t *message, size_t message_len, const char *application, const uint8_t *key_handle, size_t key_handle_len, uint8_t flags, const char *pin, struct sk_option **options, struct sk_sign_response **sign_response)
{
	struct sk_sign_response *response = NULL;
	int ret = SSH_SK_ERR_GENERAL;

	if (sign_response == NULL)
	{
		skdebug(__func__, "sign_response == NULL");
		return SSH_SK_ERR_GENERAL;
	}
	*sign_response = NULL;

	if (check_sign_load_resident_options(options) != 0)
		return SSH_SK_ERR_GENERAL;

	if (!(flags & SSH_SK_USER_PRESENCE_REQD)) //TODO: Check when this flag is set
	{
		skdebug(__func__, "WinHello API does not support no-touch-required");
		return SSH_SK_ERR_UNSUPPORTED;
	}

	if (init_winhello() != 0)
		return SSH_SK_ERR_UNSUPPORTED;

	WEBAUTHN_ASSERTION *pWebAuthNAssertion = NULL;

	HWND hWnd = GetForegroundWindow();

	size_t application_len = strlen(application) + 1;
	wchar_t *lApplication = (wchar_t *)calloc(application_len, sizeof(wchar_t));
	if (lApplication == NULL)
	{
		skdebug(__func__, "calloc lApplication failed");
		goto out;
	}
	if (convert_byte_string(application, application_len, lApplication) <= 0)
	{
		skdebug(__func__, "convert_string application failed");
		goto out;
	}

	WEBAUTHN_CLIENT_DATA WebAuthNClientData = {WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, message_len, (uint8_t *)message, WEBAUTHN_HASH_ALGORITHM_SHA_256};

	WEBAUTHN_CREDENTIAL_EX credential = {WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION, key_handle_len, (uint8_t *)key_handle, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, WEBAUTHN_CTAP_TRANSPORT_FLAGS_MASK};
	WEBAUTHN_CREDENTIAL_EX *pCredential = &credential;
	WEBAUTHN_CREDENTIAL_LIST allowCredentialList = {1, &pCredential};
	BOOL pbU2fAppId = FALSE;
	WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS WebAuthNAssertionOptions = {WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION, 60000, {0, NULL}, {0, NULL}, WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY, WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED, 0, NULL, &pbU2fAppId, NULL, &allowCredentialList};

	HRESULT hr = webAuthNAuthenticatorGetAssertion(hWnd, lApplication, &WebAuthNClientData, &WebAuthNAssertionOptions, &pWebAuthNAssertion);
	if (hr != S_OK)
	{
		skdebug(__func__, "WinHello API Error %d:%ls", hr, webAuthNGetErrorName(hr));
		goto out;
	}

	if (pWebAuthNAssertion->cbAuthenticatorData < 32 + 1 + 4)
	{
		skdebug(__func__, "Invalid response format");
		goto out;
	}

	if ((response = calloc(1, sizeof(*response))) == NULL)
	{
		skdebug(__func__, "calloc response failed");
		goto out;
	}

	response->flags = pWebAuthNAssertion->pbAuthenticatorData[32];

	response->counter = pWebAuthNAssertion->pbAuthenticatorData[33];
	response->counter <<= 8;
	response->counter |= pWebAuthNAssertion->pbAuthenticatorData[34];
	response->counter <<= 8;
	response->counter |= pWebAuthNAssertion->pbAuthenticatorData[35];
	response->counter <<= 8;
	response->counter |= pWebAuthNAssertion->pbAuthenticatorData[36];

	if (pack_sig(alg, pWebAuthNAssertion->pbSignature, pWebAuthNAssertion->cbSignature, response) != 0)
	{
		skdebug(__func__, "pack_sig failed");
		return -1;
	}

	*sign_response = response;
	response = NULL;
	ret = 0;
out:
	webAuthNFreeAssertion(pWebAuthNAssertion);
	free(lApplication);
	if (response != NULL)
	{
		free(response->sig_r);
		free(response->sig_s);
		free(response);
	}
	return ret;
}

/* Load resident keys */
int sk_load_resident_keys(const char *pin, struct sk_option **options, struct sk_resident_key ***rks, size_t *nrks)
{
	skdebug(__func__, "WinHello API does not support returning list of resident keys(yet), use internal implementation of OpenSSH(Be sure that you are running shell as administrator if needed)");
	return SSH_SK_ERR_UNSUPPORTED;
}
