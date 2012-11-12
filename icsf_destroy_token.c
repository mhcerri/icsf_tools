#include <stdlib.h>
#include <stdio.h>
#include "icsf.h"
#include "log.h"
#include "util.h"

int main(int argc, char *argv[])
{
    int rc = 0;
    LDAP *ld = NULL;
    char *uri, *dn, *pw;
    char *token_name = NULL;

    if (argc != 2) {
        printf("Usage: %s <token name>\n", base_name(argv[0]));
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

    OCK_LOG_DEBUG("Destroying token\n");
    if ((rc = icsf_destroy_token(ld, token_name)))
        goto cleanup;

cleanup:
    if (rc)
        printf("Error!\n");

    if (ld)
        icsf_logout(ld);

    return rc;
}
