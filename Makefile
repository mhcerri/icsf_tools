
CC=gcc
CFLAGS=-O0 -g -Wall -Werror \
      -I. \
      -I./ock/usr/lib/pkcs11/icsf_stdll/ \
      -I./ock/usr/include/pkcs11/ \
      -I./ock/usr/lib/pkcs11/common/
LDFLAGS=-lldap
DEPS=util.o \
     ./ock/usr/lib/pkcs11/icsf_stdll/icsf.o
TARGETS=icsf_create_token \
		icsf_destroy_token \
		icsf_list_tokens \
		icsf_create_object \
		icsf_list_objects \
		icsf_destroy_object \
		icsf_gen_secret_key \
		icsf_secret_key_encrypt \
		icsf_secret_key_encrypt_chaining \
		icsf_sasl

all: $(TARGETS)

clean:
	rm -f $(TARGETS) *.o tags

icsf_create_token: icsf_create_token.o $(DEPS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

icsf_destroy_token: icsf_destroy_token.o $(DEPS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

icsf_list_tokens: icsf_list_tokens.o $(DEPS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

icsf_create_object: icsf_create_object.o $(DEPS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

icsf_list_objects: icsf_list_objects.o $(DEPS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

icsf_destroy_object: icsf_destroy_object.o $(DEPS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

icsf_gen_secret_key: icsf_gen_secret_key.o $(DEPS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

icsf_secret_key_encrypt: icsf_secret_key_encrypt.o $(DEPS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

icsf_secret_key_encrypt_chaining: icsf_secret_key_encrypt_chaining.o $(DEPS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

icsf_sasl: icsf_sasl.o $(DEPS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

