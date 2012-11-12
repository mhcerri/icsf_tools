#include <stdlib.h>
#include <stdio.h>
#include "icsf.h"
#include "log.h"
#include "util.h"
#include "pkcs11types.h"

int main(int argc, char *argv[])
{
    int rc = 0;
    LDAP *ld = NULL;
    char *uri, *dn, *pw;
    char *token_name = NULL;
    char handle[ICSF_HANDLE_LEN];

    char type = ICSF_TOKEN_OBJECT;

    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    CK_BBOOL false_value = FALSE;
    char value[] = "This is a secret!";
    CK_ATTRIBUTE attrs[] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_TOKEN, &false_value, sizeof(false_value) },
        { CKA_VALUE, value, sizeof(value) },
    };
    CK_ULONG attrs_len = sizeof(attrs)/sizeof(attrs[0]);

    if (argc != 2) {
        printf("Usage: %s <token_name>\n",
               base_name(argv[0]));
        return 1;
    }
    token_name = argv[1];

    init_conn_data(&uri, &dn, &pw);

    OCK_LOG_DEBUG("Logging in\n");
    if ((rc = icsf_login(&ld, uri, dn, pw)))
        goto cleanup;

    OCK_LOG_DEBUG("Checking support\n");
    if ((rc = icsf_check_pkcs_extension(ld)))
        goto cleanup;

    OCK_LOG_DEBUG("Creating object\n");
    if ((rc = icsf_create_object(ld, token_name, type, attrs, attrs_len,
                                handle, sizeof(handle))))
        goto cleanup;

cleanup:
    if (rc)
        printf("Error!\n");

    if (ld)
        icsf_logout(ld);

    return rc;
}
