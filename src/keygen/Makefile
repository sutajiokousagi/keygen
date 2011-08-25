# template src/Makefile
# $Id$

include ../../../config/config.mk
AUTH_DIR=beecrypt-4.1.2

all: build

build:
	$(MAKE) -C ${AUTH_DIR} CROSS_COMPILE=$(TARGET)- DESTDIR=$(PREFIX)
	$(TARGET)-gcc  -Ibeecrypt-4.1.2/ -o keygen keygen.c beecrypt-4.1.2/.libs/libbeecrypt.a 
	$(TARGET)-gcc  -o cp_eeprom cp_eeprom.c


clean:
	$(MAKE) -C ${AUTH_DIR} clean || true
	rm -f *.o

install: build
ifeq ($(PREFIX),)
	@echo "PREFIX not specified"
	@exit 1
else
	@echo "Installing to $(PREFIX)/psp-factory/"
	mkdir -p $(PREFIX)/psp-factory/
	cp keygen $(PREFIX)/psp-factory/
	cp cp_eeprom $(PREFIX)/psp-factory/
	mkdir -p $(PREFIX)/psp-factory/rfs1/
	cp keygen-script.pl $(PREFIX)/psp-factory/rfs1/userhook1
	chmod a+x $(PREFIX)/psp-factory/rfs1/userhook1
	cp printpass.sh $(PREFIX)/psp-factory/rfs1/userhook2
	chmod a+x $(PREFIX)/psp-factory/rfs1/userhook2
	cp pubkey $(PREFIX)/psp-factory/
	cp dcid.xml $(PREFIX)/psp-factory/
endif

# unpack should NOT be phony
.PHONY: all clean install build

