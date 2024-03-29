VASQ_DIR := $(HAMO_DIR)/packages/vanilla_squad
include $(VASQ_DIR)/make.mk

HAMO_INCLUDE_FLAGS := $(patsubst %,-I%,$(VASQ_INCLUDE_DIR) $(HAMO_DIR)/include)

HAMO_LIB_DIR ?= $(HAMO_DIR)
HAMO_SHARED_LIBRARY := $(HAMO_LIB_DIR)/libhallmonitor.so
HAMO_STATIC_LIBRARY := $(HAMO_LIB_DIR)/libhallmonitor.a

HAMO_SOURCE_FILES := $(wildcard $(HAMO_DIR)/src/*.c)
HAMO_OBJECT_FILES := $(patsubst %.c,%.o,$(HAMO_SOURCE_FILES))

HAMO_HEADER_FILES := $(wildcard $(HAMO_DIR)/include/hamo/*.h) $(VASQ_HEADER_FILES)

HAMO_DEPS_FILE := $(HAMO_DIR)/deps.mk
DEPS_FILES += $(HAMO_DEPS_FILE)

ifneq ($(MAKECMDGOALS),clean)

$(HAMO_DEPS_FILE): $(HAMO_SOURCE_FILES) $(HAMO_HEADER_FILES)
	rm -f $@
	for file in $(HAMO_SOURCE_FILES); do \
	    echo "$(HAMO_DIR)/src/`$(CC) $(CFLAGS) $(HAMO_INCLUDE_FLAGS) -MM $$file`" >> $@ && \
	    echo '\t$$(CC) $$(CFLAGS) -fpic -ffunction-sections $(HAMO_INCLUDE_FLAGS) -c $$< -o $$@' >> $@; \
	done
include $(HAMO_DEPS_FILE)

endif

$(HAMO_SHARED_LIBRARY): $(HAMO_OBJECT_FILES)
	$(CC) $(LDFLAGS) -shared -o $@ $^

$(HAMO_STATIC_LIBRARY): $(HAMO_OBJECT_FILES)
	$(AR) rcs $@ $^

hamo_clean:
	@rm -f $(HAMO_SHARED_LIBRARY) $(HAMO_STATIC_LIBRARY) $(HAMO_OBJECT_FILES)

CLEAN_TARGETS += hamo_clean
