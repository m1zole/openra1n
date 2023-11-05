CFLAGS = -isysroot ~/sdks/MacOSX11.3.sdk -I./include -Wall -Wno-pointer-sign -x objective-c
CFLAGS += -Os
RA1N = openra1n
TERM = pongoterm
RSOURCE = openra1n.c lz4/lz4.c lz4/lz4hc.c
TSOURCE = pongoterm.c
ifeq ($(LIBUSB),1)
	CC = gcc
	CFLAGS += -DHAVE_LIBUSB
	LDFLAGS += -lusb-1.0
else
	CC = xcrun -sdk macosx gcc
	CFLAGS += -arch x86_64
	LDFLAGS += -framework Foundation -framework IOKit -framework CoreFoundation
endif

.PHONY: all clean payloads openra1n

all: payloads openra1n pongoterm

payloads:
	@mkdir -p include/payloads
	@for file in payloads/*; do \
		echo " XXD    $$file"; \
		xxd -i $$file > include/$$file.h; \
	done

openra1n: payloads
	@echo " CC     $(RA1N)"
	@$(CC) $(CFLAGS) $(RSOURCE) $(LDFLAGS) -o $(RA1N)

pongoterm: payloads
	@echo " CC     $(TERM)"
	@$(CC) $(CFLAGS) $(TSOURCE) $(LDFLAGS) -o $(TERM)

clean:
	@echo " CLEAN  $(BIN)"
	@rm -f $(BIN)
	@echo " CLEAN  include/payloads"
	@rm -rf include/payloads
