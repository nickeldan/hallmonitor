PCAP_DIR := $(HAMO_DIR)/packages/libpcap
PCAP_SHARED_LIBRARY := $(PCAP_DIR)/libpcap.so
PCAP_STATIC_LIBRARY := $(PCAP_DIR)/libpcap.a

$(PCAP_SHARED_LIBRARY) $(PCAP_STATIC_LIBRARY): $(PCAP_DIR)/Makefile
	cd $(PCAP_DIR) && make

PCAP_CONFIGURE_FLAGS := CFLAGS="$(CFLAGS)" --disable-largefile --enable-remote --enable-shared --disable-usb --disable-dbus --disable-rdma

$(PCAP_DIR)/Makefile:
	cd $(PCAP_DIR) && ./configure $(PCAP_CONFIGURE_FLAGS)

VASQ_DIR := $(HAMO_DIR)/packages/vanilla_squad
include $(VASQ_DIR)/make.mk

HAMO_INCLUDE_FLAGS := $(patsubst %,-I%,$(PCAP_DIR) $(VASQ_INCLUDE_DIR) $(HAMO_DIR)/include)

HAMO_SHARED_LIBRARY := $(HAMO_DIR)/libhallmonitor.so
HAMO_STATIC_LIBRARY := $(HAMO_DIR)/libhallmonitor.a

HAMO_SOURCE_FILES := $(wildcard $(HAMO_DIR)/lib/*.c)
HAMO_OBJECT_FILES := $(patsubst %.c,%.o,$(HAMO_SOURCE_FILES))
HAMO_HEADER_FILES := $(wildcard $(HAMO_DIR)/include/hamo/*.h)
HAMO_EXTERNAL_HEADER_FILES := $(foreach dir,$(PCAP_DIR) $(VASQ_INCLUDE_DIR),$(shell find $(dir) -name '*.h'))

HAMO_DEPS_FILE := $(HAMO_DIR)/deps.mk
DEPS_FILES += $(HAMO_DEPS_FILE)

$(HAMO_DEPS_FILE): $(HAMO_SOURCE_FILES) $(HAMO_HEADER_FILES) $(HAMO_EXTERNAL_HEADER_FILES)
	rm -f $@
	for file in $(HAMO_SOURCE_FILES); do \
	    echo "$(HAMO_DIR)/lib/`$(CC) $(CFLAGS) $(HAMO_INCLUDE_FLAGS) -MM $$file`" >> $@ && \
	    echo '\t$$(CC) $$(CFLAGS) -fpic -ffunction-sections $(HAMO_INCLUDE_FLAGS) -c $$< -o $$@' >> $@; \
	done
include $(HAMO_DEPS_FILE)

$(HAMO_SHARED_LIBRARY): $(HAMO_OBJECT_FILES)
	$(CC) -shared -o $@ $^

$(HAMO_STATIC_LIBRARY): $(HAMO_OBJECT_FILES)
	$(AR) rcs $@ $^

hamo_clean:
	cd $(PCAP_DIR) && if [ -f Makefile ]; then make distclean; fi
	rm -f $(HAMO_SHARED_LIBRARY) $(HAMO_STATIC_LIBRARY) $(HAMO_OBJECT_FILES)

CLEAN_TARGETS += hamo_clean