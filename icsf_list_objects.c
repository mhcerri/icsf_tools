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
    const char *token_name = NULL;
    struct icsf_object_record records[2];
    struct icsf_object_record *previous = NULL;
    size_t object_num = 0;
    size_t records_len;
    size_t i;

    if (argc != 2) {
        printf("Usage: %s <token_name>\n", base_name(argv[0]));
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

    OCK_LOG_DEBUG("Listing tokens\n");

    do {
        records_len = sizeof(records)/sizeof(records[0]);

        if ((rc = icsf_list_objects(ld, token_name, previous, records,
                                    &records_len, 0)))
            goto cleanup;

        for (i = 0; i < records_len; i++) {
            printf("Object #:      %lu\nToken name:    %s\n"
                   "Sequence:      %lu\nID:            %c\n\n",
                   object_num++, records[i].token_name, records[i].sequence,
                   records[i].id);
        }
        if (records_len)
            previous = &records[records_len - 1];
    } while (records_len);


cleanup:
    if (rc)
        printf("Error!\n");

    if (ld)
        icsf_logout(ld);

    return rc;
}
