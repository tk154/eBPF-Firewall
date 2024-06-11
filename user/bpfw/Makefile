CC 	   := gcc
LDLIBS := -lbpf -lelf -lz -lnetfilter_conntrack -lnfnetlink -lmnl

SRC_DIR := .
OUT_DIR := bin

MAIN_SRC := main.c
SOURCES  := flowtrack.c bpf_loader/bpf_loader.c netlink/netlink.c \
	netfilter/netfilter.c netfilter/conntrack/conntrack.c netfilter/conntrack/nat.c

ifdef OPENWRT_DIR
include ../OpenWrt.mk
CPPFLAGS += -DOPENWRT_UCODE
LDLIBS   += -lucode -ljson-c
OUT_DIR  := $(OUT_DIR)/$(TARGET)
SOURCES  += ucode/ucode.c
endif

OUT_BIN := $(OUT_DIR)/bpfw

OBJECTS := $(patsubst %.c,$(OUT_DIR)/%.o,$(notdir $(SOURCES)))
vpath %.c $(dir $(SOURCES))

$(OUT_BIN): $(MAIN_SRC) $(OBJECTS)
	$(CC) $(CPPFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(OUT_DIR)/%.o: $(SRC_DIR)/%.c | $(OUT_DIR)
	$(CC) $(CPPFLAGS) -c $< -o $@

$(OUT_DIR):
	@mkdir -p $(OUT_DIR)

clean:
	@rm -rf $(OUT_DIR)
