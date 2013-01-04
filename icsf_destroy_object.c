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
    struct icsf_object_record obj;

    if (argc != 4) {
        printf("Usage: %s <token name> <sequence> [S|T]\n", base_name(argv[0]));
        return 1;
    }
    snprintf(obj.token_name, sizeof(obj.token_name), "%s", argv[1]);
    obj.sequence = (unsigned long) atoll(argv[2]);
    obj.id = (char) toupper(*argv[3]);

    init_conn_data(&uri, &dn, &pw);

    OCK_LOG_DEBUG("Logging in\n");
    if ((rc = icsf_login(&ld, uri, dn, pw)))
        goto cleanup;

    OCK_LOG_DEBUG("Checking support\n");
    if ((rc = icsf_check_pkcs_extension(ld)))
        goto cleanup;

    OCK_LOG_DEBUG("Destroying token\n");
    if ((rc = icsf_destroy_object(ld, &obj)))
        goto cleanup;

cleanup:
    if (rc)
        printf("Error!\n");

    if (ld)
        icsf_logout(ld);

    return rc;
}
