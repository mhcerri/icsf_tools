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
    struct icsf_token_record records[2];
    struct icsf_token_record *previous = NULL;
    size_t token_num = 0;
    size_t records_len;
    size_t i;

    if (argc != 1) {
        printf("Usage: %s\n", base_name(argv[0]));
        return 1;
    }

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

        if ((rc = icsf_list_tokens(ld, previous, records, &records_len)))
            goto cleanup;

        for (i = 0; i < records_len; i++) {
            printf("Token #:      %lu\nToken name:   %s\nManufacturer: %s\n"
                   "Model:        %s\nSerial:       %s\nLast changed: %s %s\n"
                   "Read-only:    %s\n\n",
                   (long unsigned int) token_num++, records[i].name, records[i].manufacturer,
                   records[i].model, records[i].serial,
                   records[i].date, records[i].time,
                   ICSF_IS_TOKEN_READ_ONLY(records[i].flags) ? "yes" : "no");
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
