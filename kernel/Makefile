CLANG  := clang
CFLAGS := -O2 -g -Wall -target bpf

SRC_DIR := .
OBJ_DIR := obj

BPF_NAME := bpfw
SOURCE   := $(SRC_DIR)/$(BPF_NAME).c
HEADERS  := $(wildcard $(SRC_DIR)/*.h)

XDP_LE_OBJ_FILE := $(OBJ_DIR)/xdp_le_$(BPF_NAME).o
XDP_BE_OBJ_FILE := $(OBJ_DIR)/xdp_be_$(BPF_NAME).o
TC_LE_OBJ_FILE  := $(OBJ_DIR)/tc_le_$(BPF_NAME).o
TC_BE_OBJ_FILE  := $(OBJ_DIR)/tc_be_$(BPF_NAME).o

XDP_FLAGS := -DXDP_PROGRAM
TC_FLAGS  := -DTC_PROGRAM
LE_FLAGS  := -mlittle-endian
BE_FLAGS  := -mbig-endian

ifdef FLOW_MAP_MAX_ENTRIES
OPTIONS += -DFLOW_MAP_MAX_ENTRIES=$(FLOW_MAP_MAX_ENTRIES)
endif

all: xdp-le tc-le xdp-be tc-be

xdp: xdp-le xdp-be

tc: tc-le tc-be

le: xdp-le tc-le

be: xdp-be tc-be

xdp-le: $(XDP_LE_OBJ_FILE)

tc-le: $(TC_LE_OBJ_FILE)

xdp-be: $(XDP_BE_OBJ_FILE)

tc-be: $(TC_BE_OBJ_FILE)

clean:
	@rm -rf $(OBJ_DIR)

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

define BPF_COMPILE
$(1): CUSTOM_FLAGS := $(2)
$(1): $(SOURCE) $(HEADERS) | $(OBJ_DIR)
	$(CLANG) $(CFLAGS) $$(CUSTOM_FLAGS) -c $$< -o $$@
endef

$(eval $(call BPF_COMPILE,$(XDP_LE_OBJ_FILE),$(LE_FLAGS) $(XDP_FLAGS) $(OPTIONS)))
$(eval $(call BPF_COMPILE,$(XDP_BE_OBJ_FILE),$(BE_FLAGS) $(XDP_FLAGS) $(OPTIONS)))
$(eval $(call BPF_COMPILE,$(TC_LE_OBJ_FILE),$(LE_FLAGS) $(TC_FLAGS) $(OPTIONS)))
$(eval $(call BPF_COMPILE,$(TC_BE_OBJ_FILE),$(BE_FLAGS) $(TC_FLAGS) $(OPTIONS)))
