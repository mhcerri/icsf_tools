#include <stdlib.h>
#include <stdio.h>
#include "icsf.h"
#include "log.h"
#include "util.h"

int main(int argc, char *argv[])
{
    int rc = 0;
    LDAP *ld = NULL;
    char *uri, *cert, *key, *ca;

    if (argc != 1) {
        printf("Usage: %s\n", base_name(argv[0]));
        return 1;
    }

    init_sasl_conn_data(&uri, &cert, &key, &ca);

    OCK_LOG_DEBUG("Logging in\n");
    if ((rc = icsf_sasl_login(&ld, uri, cert, key, ca, NULL)))
        goto cleanup;

    OCK_LOG_DEBUG("Checking support\n");
    if ((rc = icsf_check_pkcs_extension(ld)))
        goto cleanup;

cleanup:
    if (rc)
        printf("Error!\n");

    if (ld)
        icsf_logout(ld);

    return rc;
}
