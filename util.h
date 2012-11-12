#ifndef UTIL_H
#define UTIL_H

#include <lber.h>
#include "pkcs11types.h"

void
set_ldap_debug(void);

const char *
base_name(const char *path);

void
init_conn_data(char **uri, char **dn, char **pass);

void
init_sasl_conn_data(char **uri, char **cert, char **key, char **ca);

int
dump_berval_to_file(struct berval *berval, const char *file);

CK_ULONG
pkcs11_attr_name_to_type(const char *attr_name);

#endif
