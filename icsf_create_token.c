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
    char *manufacturer_id = NULL;
    char *model = NULL;
    char *serial_number = NULL;

    if (argc != 5) {
        printf("Usage: %s <token_name> <manufacturer> <model> "
               "<serial>\n", base_name(argv[0]));
        return 1;
    }
    token_name = argv[1];
    manufacturer_id = argv[2];
    model = argv[3];
    serial_number = argv[4];

    init_conn_data(&uri, &dn, &pw);

    OCK_LOG_DEBUG("Logging in\n");
    if ((rc = icsf_login(&ld, uri, dn, pw)))
        goto cleanup;

    OCK_LOG_DEBUG("Checking support\n");
    if ((rc = icsf_check_pkcs_extension(ld)))
        goto cleanup;

    OCK_LOG_DEBUG("Initializing token\n");
    if ((rc = icsf_create_token(ld, token_name, manufacturer_id, model,
                                serial_number)))
        goto cleanup;

cleanup:
    if (rc)
        printf("Error!\n");

    if (ld)
        icsf_logout(ld);

    return rc;
}
