debug ?= no

CLEAN_TARGETS :=
DEPS_FILES :=

CFLAGS := -std=gnu99 -fdiagnostics-color -Wall -Wextra -DVASQ_ALLOW_PLACEHOLDER -DVASQ_WARN_PLACEHOLDER
ifeq ($(debug),yes)
	CFLAGS += -O0 -g -DDEBUG
else
	CFLAGS += -O3 -DNDEBUG
endif

all: hamo

HAMO_DIR := .
include make.mk

MAIN_DEPS_FILE := main_deps.mk
DEPS_FILES += $(MAIN_DEPS_FILE)

ifneq ($(MAKECMDGOALS),clean)

$(MAIN_DEPS_FILE): hallmonitor/main.c $(HAMO_HEADER_FILES) $(HAMO_EXTERNAL_HEADER_FILES)
	rm -f $@
	echo "hallmonitor/`$(CC) $(HAMO_INCLUDE_FLAGS) -MM $<`" >> $@
	echo '\t$$(CC) $$(CFLAGS) -fpic -ffunction-sections $(HAMO_INCLUDE_FLAGS) -c $$< -o $$@' >> $@
include $(MAIN_DEPS_FILE)

endif

.PHONY: all libs clean $(CLEAN_TARGETS)

libs: $(HAMO_SHARED_LIBRARY) $(HAMO_STATIC_LIBRARY)

hamo: hallmonitor/main.o $(HAMO_STATIC_LIBRARY) $(VASQ_STATIC_LIBRARY)
	$(CC) $(CFLAGS) $(HAMO_INCLUDE_FLAGS) -o $@ $^ -lpcap

clean: $(CLEAN_TARGETS)
	@rm -f hamo hallmonitor/main.o $(DEPS_FILES)
