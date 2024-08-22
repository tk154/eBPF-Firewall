CLANG  := clang
CFLAGS := -O2 -g -Wall -target bpf

SRC_DIR := .
OBJ_DIR := obj

BPF_NAME := bpfw
SOURCE   := $(SRC_DIR)/$(BPF_NAME).c
HEADERS  := $(wildcard $(SRC_DIR)/*.h)

LE_OBJ_FILE := $(OBJ_DIR)/$(BPF_NAME)_le.o
BE_OBJ_FILE := $(OBJ_DIR)/$(BPF_NAME)_be.o

LE_FLAG := -mlittle-endian
BE_FLAG := -mbig-endian

NO_XDP_FLAG := -DBPFW_NO_XDP
NO_TC_FLAG  := -DBPFW_NO_TC

all: le be

le: ENDIAN_FLAG := $(LE_FLAG)
le: $(LE_OBJ_FILE)

be: ENDIAN_FLAG := $(BE_FLAG)
be: $(BE_OBJ_FILE)

.PHONY: .xdp-common .tc-common
.xdp-common:
	$(eval BPFW_FLAG := $(NO_TC_FLAG))

.tc-common:
	$(eval BPFW_FLAG := $(NO_XDP_FLAG))

xdp: .xdp-common le be

tc: .tc-common le be

xdp-le: .xdp-common le

xdp-be: .xdp-common be

tc-le: .tc-common le

tc-be: .tc-common be

clean:
	@rm -rf $(OBJ_DIR)

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

define BPF_COMPILE
$(1): $(SOURCE) $(HEADERS) | $(OBJ_DIR)
	$(CLANG) $(CFLAGS) $$(ENDIAN_FLAG) $$(BPFW_FLAG) -c $$< -o $$@
endef

$(eval $(call BPF_COMPILE,$(LE_OBJ_FILE)))
$(eval $(call BPF_COMPILE,$(BE_OBJ_FILE)))
