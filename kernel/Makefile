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

all: le be

le: $(LE_OBJ_FILE)

be: $(BE_OBJ_FILE)

clean:
	@rm -rf $(OBJ_DIR)

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

define BPF_COMPILE
$(1): CFLAGS += $(2)
$(1): $(SOURCE) $(HEADERS) | $(OBJ_DIR)
	$(CLANG) $$(CFLAGS) -c $$< -o $$@
endef

$(eval $(call BPF_COMPILE,$(LE_OBJ_FILE),$(LE_FLAG)))
$(eval $(call BPF_COMPILE,$(BE_OBJ_FILE),$(BE_FLAG)))
