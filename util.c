#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ldap.h>
#include "util.h"
#include "log.h"

void
set_ldap_debug(void)
{
    int level;
    const char *str_level;
    
    if ((str_level = getenv("ICSF_DEBUG")) == NULL)
        return;
    
    level = atoi(str_level);
    if (level < 0)
        level = 0;
    else if (level > 7)
        level = 7;

    OCK_LOG_DEBUG("Setting LDAP debug level to %d\n", level);
    if (ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &level))
        OCK_LOG_DEBUG("Failed to set LDAP debug level: %s\n", str_level);
}

const char *
base_name(const char *path)
{
    const char *basename = strrchr(path, '/');
    if (!basename)
        basename = path;
    else
        ++basename;
    return basename;
}

#define _GET_ENV(name, var)                                 \
    if (!((var) = getenv(name))) {                          \
        fprintf(stderr, "Env var $" name " not set.\n");    \
        exit(1);                                            \
    }

void
init_conn_data(char **uri, char **dn, char **pass)
{
    _GET_ENV("ICSF_URI", *uri);
    _GET_ENV("ICSF_DN", *dn);
    _GET_ENV("ICSF_PASSWD", *pass);
    set_ldap_debug();
}

void
init_sasl_conn_data(char **uri, char **cert, char **key, char **ca)
{
    _GET_ENV("ICSF_SASL_URI", *uri);
    _GET_ENV("ICSF_SASL_CERT", *cert);
    _GET_ENV("ICSF_SASL_KEY", *key);
    _GET_ENV("ICSF_SASL_CA", *ca);
    set_ldap_debug();
}

int
dump_berval_to_file(struct berval *berval, const char *file)
{
    int rc = -1;
    FILE *fh = NULL;

    fh = fopen(file, "w+");
    if (fh == NULL) {
        OCK_LOG_DEBUG("Failed to open file.\n");
        goto cleanup;
    }
        
    if (fwrite(berval->bv_val, 1, berval->bv_len, fh) != berval->bv_len) {
        OCK_LOG_DEBUG("Failed to write to file.\n");
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (fh && fclose(fh)) {
        OCK_LOG_DEBUG("Failed to close file.\n");
        rc = -1;
    }
    return rc;
}

CK_ULONG
pkcs11_attr_name_to_type(const char *attr_name)
{
    #define ATTR_NAME_TO_TYPE(_type) \
        if (strcmp(#_type, attr_name) == 0) \
            return _type
    
    ATTR_NAME_TO_TYPE(CKA_CLASS);
    ATTR_NAME_TO_TYPE(CKA_TOKEN);
    ATTR_NAME_TO_TYPE(CKA_PRIVATE);
    ATTR_NAME_TO_TYPE(CKA_LABEL);
    ATTR_NAME_TO_TYPE(CKA_APPLICATION);
    ATTR_NAME_TO_TYPE(CKA_VALUE);
    ATTR_NAME_TO_TYPE(CKA_OBJECT_ID);
    ATTR_NAME_TO_TYPE(CKA_CERTIFICATE_TYPE);
    ATTR_NAME_TO_TYPE(CKA_ISSUER);
    ATTR_NAME_TO_TYPE(CKA_SERIAL_NUMBER);
    ATTR_NAME_TO_TYPE(CKA_AC_ISSUER);
    ATTR_NAME_TO_TYPE(CKA_OWNER);
    ATTR_NAME_TO_TYPE(CKA_ATTR_TYPES);
    ATTR_NAME_TO_TYPE(CKA_TRUSTED);
    ATTR_NAME_TO_TYPE(CKA_KEY_TYPE);
    ATTR_NAME_TO_TYPE(CKA_SUBJECT);
    ATTR_NAME_TO_TYPE(CKA_ID);
    ATTR_NAME_TO_TYPE(CKA_SENSITIVE);
    ATTR_NAME_TO_TYPE(CKA_ENCRYPT);
    ATTR_NAME_TO_TYPE(CKA_DECRYPT);
    ATTR_NAME_TO_TYPE(CKA_WRAP);
    ATTR_NAME_TO_TYPE(CKA_UNWRAP);
    ATTR_NAME_TO_TYPE(CKA_SIGN);
    ATTR_NAME_TO_TYPE(CKA_SIGN_RECOVER);
    ATTR_NAME_TO_TYPE(CKA_VERIFY);
    ATTR_NAME_TO_TYPE(CKA_VERIFY_RECOVER);
    ATTR_NAME_TO_TYPE(CKA_DERIVE);
    ATTR_NAME_TO_TYPE(CKA_START_DATE);
    ATTR_NAME_TO_TYPE(CKA_END_DATE);
    ATTR_NAME_TO_TYPE(CKA_MODULUS);
    ATTR_NAME_TO_TYPE(CKA_MODULUS_BITS);
    ATTR_NAME_TO_TYPE(CKA_PUBLIC_EXPONENT);
    ATTR_NAME_TO_TYPE(CKA_PRIVATE_EXPONENT);
    ATTR_NAME_TO_TYPE(CKA_PRIME_1);
    ATTR_NAME_TO_TYPE(CKA_PRIME_2);
    ATTR_NAME_TO_TYPE(CKA_EXPONENT_1);
    ATTR_NAME_TO_TYPE(CKA_EXPONENT_2);
    ATTR_NAME_TO_TYPE(CKA_COEFFICIENT);
    ATTR_NAME_TO_TYPE(CKA_PRIME);
    ATTR_NAME_TO_TYPE(CKA_SUBPRIME);
    ATTR_NAME_TO_TYPE(CKA_BASE);
    ATTR_NAME_TO_TYPE(CKA_PRIME_BITS);
    ATTR_NAME_TO_TYPE(CKA_SUBPRIME_BITS);
    ATTR_NAME_TO_TYPE(CKA_VALUE_BITS);
    ATTR_NAME_TO_TYPE(CKA_VALUE_LEN);
    ATTR_NAME_TO_TYPE(CKA_EXTRACTABLE);
    ATTR_NAME_TO_TYPE(CKA_LOCAL);
    ATTR_NAME_TO_TYPE(CKA_NEVER_EXTRACTABLE);
    ATTR_NAME_TO_TYPE(CKA_ALWAYS_SENSITIVE);
    ATTR_NAME_TO_TYPE(CKA_KEY_GEN_MECHANISM);
    ATTR_NAME_TO_TYPE(CKA_MODIFIABLE);
    ATTR_NAME_TO_TYPE(CKA_ECDSA_PARAMS);
    ATTR_NAME_TO_TYPE(CKA_EC_PARAMS);
    ATTR_NAME_TO_TYPE(CKA_EC_POINT);
    ATTR_NAME_TO_TYPE(CKA_SECONDARY_AUTH);
    ATTR_NAME_TO_TYPE(CKA_AUTH_PIN_FLAGS);
    ATTR_NAME_TO_TYPE(CKA_HW_FEATURE_TYPE);
    ATTR_NAME_TO_TYPE(CKA_RESET_ON_INIT);
    ATTR_NAME_TO_TYPE(CKA_HAS_RESET);
    ATTR_NAME_TO_TYPE(CKA_VENDOR_DEFINED);
    ATTR_NAME_TO_TYPE(CKA_IBM_OPAQUE);

    #undef ATTR_NAME_TO_TYPE

    return -1;
}
