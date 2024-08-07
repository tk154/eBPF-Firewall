CC 	   := gcc
LDLIBS := -lbpf -lelf -lz -lnetfilter_conntrack -lnfnetlink -lmnl

SRC_DIR := .
BIN_DIR := bin

MAIN_SRC := main.c
SOURCES  := flowtrack.c bpf_loader/bpf_loader.c netlink/netlink.c netlink/dsa/dsa.c \
	netlink/pppoe/pppoe.c conntrack/conntrack.c conntrack/nat.c logging/logging.c

ifdef OPENWRT_DIR
include ../OpenWrt.mk
ARCH_DIR := $(BIN_DIR)/$(ARCH)
else
ARCH_DIR := $(BIN_DIR)/host
endif

ifdef OPENWRT_UCODE
CFLAGS  += -DOPENWRT_UCODE
LDLIBS  += -lucode -ljson-c
SOURCES += ucode/ucode.c
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
