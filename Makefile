debug ?= no

CLEAN_TARGETS :=
DEPS_FILES :=

CFLAGS := -std=gnu11 -fdiagnostics-color -Wall -Wextra
ifeq ($(debug),yes)
	CFLAGS += -O0 -g -DDEBUG
else
	CFLAGS += -O3 -DNDEBUG
endif

all: hamo

HAMO_DIR := .
include make.mk

MAIN_HEADER_FILES := $(wildcard hallmonitor/*.h)
MAIN_SOURCE_FILES := $(wildcard hallmonitor/*.c)
MAIN_OBJECT_FILES := $(patsubst %.c,%.o,$(MAIN_SOURCE_FILES))
MAIN_LDFLAGS := -lpcap

ifeq ($(shell uname),Linux)

REAP_DIR := packages/reap
include $(REAP_DIR)/make.mk

MAIN_LDFLAGS += -pthread

endif

MAIN_DEPS_FILE := main_deps.mk
DEPS_FILES += $(MAIN_DEPS_FILE)

ifneq ($(MAKECMDGOALS),clean)

$(MAIN_DEPS_FILE): $(MAIN_SOURCE_FILES) $(MAIN_HEADER_FILES) $(REAP_HEADER_FILES) $(HAMO_HEADER_FILES)
	rm -f $@
	for file in $(MAIN_SOURCE_FILES); do \
	    echo "hallmonitor/`$(CC) $(HAMO_INCLUDE_FLAGS) $(REAP_INCLUDE_FLAGS) -MM $$file`" >> $@ && \
	    echo '\t$$(CC) $$(CFLAGS) -fpic -ffunction-sections $(HAMO_INCLUDE_FLAGS) $(REAP_INCLUDE_FLAGS) -c $$< -o $$@' >> $@; \
	done
include $(MAIN_DEPS_FILE)

endif

.PHONY: all libs format clean $(CLEAN_TARGETS)

libs: $(HAMO_SHARED_LIBRARY) $(HAMO_STATIC_LIBRARY)

hamo: $(MAIN_OBJECT_FILES) $(HAMO_STATIC_LIBRARY) $(REAP_STATIC_LIBRARY) $(VASQ_STATIC_LIBRARY)
	$(CC) $(CFLAGS) $(HAMO_INCLUDE_FLAGS) -o $@ $^ $(MAIN_LDFLAGS)

format:
	find . -path ./packages -prune -o -name '*.[hc]' -print0 | xargs -0 -n 1 clang-format -i

clean: $(CLEAN_TARGETS)
	@rm -f hamo $(MAIN_OBJECT_FILES) $(DEPS_FILES)
