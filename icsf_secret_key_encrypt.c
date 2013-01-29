#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include "icsf.h"
#include "log.h"
#include "util.h"

int main(int argc, char *argv[])
{
    int rc = 0;
    LDAP *ld = NULL;
    char *uri, *dn, *pw;

    struct icsf_object_record key;
    CK_MECHANISM mech = { CKM_AES_ECB, NULL, 0UL };

    char clear_text[32] = "This is a clear text!";
    size_t clear_text_len = sizeof(clear_text);

    char cipher_text[sizeof(clear_text)] = { 0, };
    size_t cipher_text_len = sizeof(cipher_text);

    if (argc != 4) {
        printf("Usage: %s <token name> <sequence> [S|T]\n", base_name(argv[0]));
        return 1;
    }
    snprintf(key.token_name, sizeof(key.token_name), "%s", argv[1]);
    key.sequence = (unsigned long) atoll(argv[2]);
    key.id = (char) toupper(*argv[3]);

    init_conn_data(&uri, &dn, &pw);

    OCK_LOG_DEBUG("Logging in\n");
    if ((rc = icsf_login(&ld, uri, dn, pw)))
        goto cleanup;

    OCK_LOG_DEBUG("Checking support\n");
    if ((rc = icsf_check_pkcs_extension(ld)))
        goto cleanup;

    OCK_LOG_DEBUG("Encrypting\n");
    if ((rc = icsf_secret_key_encrypt(ld, NULL, &key, &mech, ICSF_CHAINING_ONLY,
				      clear_text, clear_text_len,
				      cipher_text, &cipher_text_len,
				      NULL, NULL)))
        goto cleanup;
    OCK_LOG_DEBUG("cipher_text_len = %lu\n", (unsigned long) cipher_text_len);

    memset(clear_text, 0, clear_text_len);

    OCK_LOG_DEBUG("Decrypting\n");
    if ((rc = icsf_secret_key_decrypt(ld, NULL, &key, &mech, ICSF_CHAINING_ONLY,
				      cipher_text, cipher_text_len,
				      clear_text, &clear_text_len,
				      NULL, NULL)))
        goto cleanup;
    OCK_LOG_DEBUG("clear_text_len= %lu\n", (unsigned long) clear_text_len);

    printf("Data: '%s'\n", clear_text);

cleanup:
    if (rc)
        printf("Error: %d\n", (int) rc);

    if (ld)
        icsf_logout(ld);

    return rc;
}
