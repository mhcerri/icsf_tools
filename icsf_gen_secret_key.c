#include <stdlib.h>
#include <stdio.h>
#include "icsf.h"
#include "log.h"
#include "util.h"
#include "pkcs11types.h"

//#define SSL

int main(int argc, char *argv[])
{
    int rc = 0;
    LDAP *ld = NULL;
    char *uri, *dn, *pw;
    char *token_name = NULL;
    struct icsf_object_record obj;

#ifndef SSL
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_AES;
    CK_ULONG key_len = 16;
    CK_BBOOL is_token_obj = TRUE;
    CK_ATTRIBUTE attrs[] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
	{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
        { CKA_TOKEN, &is_token_obj, sizeof(is_token_obj) },
    };
    CK_ULONG attrs_len = sizeof(attrs)/sizeof(attrs[0]);
    CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL, 0UL };
#else
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    CK_BBOOL is_token_obj = TRUE;
    CK_ATTRIBUTE attrs[] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_TOKEN, &is_token_obj, sizeof(is_token_obj) },
    };
    CK_ULONG attrs_len = sizeof(attrs)/sizeof(attrs[0]);
    CK_VERSION version = { 3, 0};
    CK_MECHANISM mech = {
	    CKM_SSL3_PRE_MASTER_KEY_GEN,
	    &version,
	    sizeof(version),
    };
#endif

    if (argc != 2) {
        printf("Usage: %s <token_name>\n",
               base_name(argv[0]));
        return 1;
    }
    token_name = argv[1];

    OCK_LOG_DEBUG("Key type: %s\n", (key_type == CKK_AES) ? "AES" : "GENERIC");

    init_conn_data(&uri, &dn, &pw);

    OCK_LOG_DEBUG("Logging in\n");
    if ((rc = icsf_login(&ld, uri, dn, pw)))
        goto cleanup;

    OCK_LOG_DEBUG("Checking support\n");
    if ((rc = icsf_check_pkcs_extension(ld)))
        goto cleanup;


    OCK_LOG_DEBUG("Creating object\n");
    if ((rc = icsf_generate_secret_key(ld, token_name, &mech, attrs, attrs_len,
				    &obj)))
        goto cleanup;

    OCK_LOG_DEBUG("Object created: token_name=\"%s\", seq=%lu, id=%c\n",
                  obj.token_name, obj.sequence, obj.id);

cleanup:
    if (rc)
        printf("Error!\n");

    if (ld)
        icsf_logout(ld);

    return rc;
}
