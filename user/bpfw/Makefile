CC 	   := gcc
LDLIBS := -lbpf -lelf -lz -lnetfilter_conntrack -lnfnetlink -lmnl

SRC_DIR  := .
BIN_DIR  := bin
ARCH_DIR := $(BIN_DIR)/host

MAIN_SRC 	 := $(SRC_DIR)/main.c
SOURCES  	 := $(shell find -name "*.c" ! -wholename "$(MAIN_SRC)")

ifdef OPENWRT
include ../OpenWrt.mk
ARCH_DIR := $(BIN_DIR)/$(ARCH)
endif

OUT_BIN := $(ARCH_DIR)/bpfw

OBJECTS := $(patsubst %.c,$(ARCH_DIR)/%.o,$(notdir $(SOURCES)))
vpath %.c $(dir $(SOURCES))

$(OUT_BIN): $(MAIN_SRC) $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(ARCH_DIR)/%.o: $(SRC_DIR)/%.c | $(ARCH_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(ARCH_DIR):
	@mkdir -p $(ARCH_DIR)

clean:
	@rm -rf $(BIN_DIR)
