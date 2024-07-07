CC 	   := gcc
LDLIBS := -lbpf -lelf -lz -lnetfilter_conntrack -lnfnetlink -lmnl

SRC_DIR := .
OUT_DIR := bin

MAIN_SRC := main.c
SOURCES  := flowtrack.c bpf_loader/bpf_loader.c netlink/netlink.c \
	netlink/pppoe/pppoe.c conntrack/conntrack.c conntrack/nat.c logging/logging.c

ifdef OPENWRT_DIR
include ../OpenWrt.mk
BIN_DIR := $(OUT_DIR)/$(TARGET)
else
BIN_DIR := $(OUT_DIR)/host
endif

ifdef OPENWRT_UCODE
CPPFLAGS += -DOPENWRT_UCODE
LDLIBS   += -lucode -ljson-c
SOURCES  += ucode/ucode.c
endif

OUT_BIN := $(BIN_DIR)/bpfw

OBJECTS := $(patsubst %.c,$(BIN_DIR)/%.o,$(notdir $(SOURCES)))
vpath %.c $(dir $(SOURCES))

$(OUT_BIN): $(MAIN_SRC) $(OBJECTS)
	$(CC) $(CPPFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(BIN_DIR)/%.o: $(SRC_DIR)/%.c | $(BIN_DIR)
	$(CC) $(CPPFLAGS) -c $< -o $@

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

clean:
	@rm -rf $(OUT_DIR)
