#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include "icsf.h"
#include "log.h"
#include "util.h"

static int
encrypt(LDAP *ld, struct icsf_object_record *key,
        CK_MECHANISM_PTR mech,
        const char *clear_text, size_t clear_text_len,
        char *cipher_text, size_t *p_cipher_text_len)
{
    int rc;
    size_t clear_done = 0;
    size_t cipher_done = 0;
    size_t cipher_block;
    size_t block_size = 32;
    char chaining_data[ICSF_CHAINING_DATA_LEN] = { 0, };
    size_t chaining_data_len = sizeof(chaining_data);

    cipher_block = block_size;
    rc = icsf_secret_key_encrypt(ld, NULL, key, mech, ICSF_CHAINING_INITIAL,
                                 clear_text, block_size,
                                 cipher_text, &cipher_block,
                                 chaining_data, &chaining_data_len);
    if (rc) {
        OCK_LOG_DEBUG("Initial failed.\n");
        return 1;
    }
    clear_done += block_size;
    cipher_done += cipher_block;

    while (clear_done < (clear_text_len - block_size)) {
        cipher_block = block_size;
        rc = icsf_secret_key_encrypt(ld, NULL, key, mech,
                                     ICSF_CHAINING_CONTINUE,
                                     clear_text + clear_done, block_size,
                                     cipher_text + cipher_done, &cipher_block,
                                     chaining_data, &chaining_data_len);
        if (rc) {
            OCK_LOG_DEBUG("Continue failed.\n");
            return 1;
        }
        clear_done += block_size;
        cipher_done += cipher_block;
    }

    cipher_block = *p_cipher_text_len - cipher_done;
    rc = icsf_secret_key_encrypt(ld, NULL, key, mech, ICSF_CHAINING_FINAL,
                                 clear_text + clear_done,
                                 clear_text_len - clear_done,
                                 cipher_text + cipher_done, &cipher_block,
                                 chaining_data, &chaining_data_len);
    if (rc) {
        OCK_LOG_DEBUG("Final failed.\n");
        return 1;
    }
    clear_done += block_size;
    cipher_done += cipher_block;

    *p_cipher_text_len = cipher_done;
    return 0;
}

static int
decrypt(LDAP *ld, struct icsf_object_record *key,
        CK_MECHANISM_PTR mech,
        const char *cipher_text, size_t cipher_text_len,
        char *clear_text, size_t *p_clear_text_len)
{
    int rc;
    size_t cipher_done = 0;
    size_t clear_done = 0;
    size_t clear_block;
    size_t block_size = 16;
    char chaining_data[ICSF_CHAINING_DATA_LEN] = { 0, };
    size_t chaining_data_len = sizeof(chaining_data);

    clear_block = block_size;
    rc = icsf_secret_key_decrypt(ld, NULL, key, mech, ICSF_CHAINING_INITIAL,
                                 cipher_text, block_size,
                                 clear_text, &clear_block,
                                 chaining_data, &chaining_data_len);
    if (rc) {
        OCK_LOG_DEBUG("Initial failed.\n");
        return 1;
    }
    cipher_done += block_size;
    clear_done += clear_block;

    while (cipher_done < (cipher_text_len - block_size)) {
        clear_block = block_size;
        rc = icsf_secret_key_decrypt(ld, NULL, key, mech,
                                     ICSF_CHAINING_CONTINUE,
                                     cipher_text + cipher_done, block_size,
                                     clear_text + clear_done, &clear_block,
                                     chaining_data, &chaining_data_len);
        if (rc) {
            OCK_LOG_DEBUG("Continue failed.\n");
            return 1;
        }
        cipher_done += block_size;
        clear_done += clear_block;
    }

    clear_block = *p_clear_text_len - clear_done;
    rc = icsf_secret_key_decrypt(ld, NULL, key, mech, ICSF_CHAINING_FINAL,
                                 cipher_text + cipher_done,
                                 cipher_text_len - cipher_done,
                                 clear_text + clear_done, &clear_block,
                                 chaining_data, &chaining_data_len);
    if (rc) {
        OCK_LOG_DEBUG("Final failed.\n");
        return 1;
    }
    cipher_done += block_size;
    clear_done += clear_block;

    *p_clear_text_len = clear_done;
    return 0;
}

int main(int argc, char *argv[])
{
    int rc = 0;
    LDAP *ld = NULL;
    char *uri, *dn, *pw;
    char *msg = "This is a message! ";
    size_t msg_len = strlen(msg);
    size_t len = 0;

    struct icsf_object_record key;
    CK_MECHANISM mech = { CKM_AES_CBC, "1234567890abcdef", 16UL };

    char clear_text[128] = { 0, };
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

    while ((len + msg_len) < clear_text_len) {
        strcpy(clear_text + len, msg);
        len += msg_len;
    }

    init_conn_data(&uri, &dn, &pw);

    OCK_LOG_DEBUG("Logging in\n");
    if ((rc = icsf_login(&ld, uri, dn, pw)))
        goto cleanup;

    OCK_LOG_DEBUG("Checking support\n");
    if ((rc = icsf_check_pkcs_extension(ld)))
        goto cleanup;

    OCK_LOG_DEBUG("Encrypting\n");

    if ((rc = encrypt(ld, &key, &mech, clear_text, clear_text_len,
                      cipher_text, &cipher_text_len)))
        goto cleanup;

    memset(clear_text, 0, clear_text_len);

    OCK_LOG_DEBUG("Decrypting\n");
    if ((rc = decrypt(ld, &key, &mech, cipher_text, cipher_text_len,
                      clear_text, &clear_text_len)))
        goto cleanup;

    printf("Data: '%s' (%lu)\n", clear_text, (unsigned long) clear_text_len);

cleanup:
    if (rc)
        printf("Error: %d\n", (int) rc);

    if (ld)
        icsf_logout(ld);

    return rc;
}
