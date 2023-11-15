CLANG := clang
CFLAGS := -O2 -g -Wall -target bpf

SRC_DIR := .
OBJ_DIR := obj

SRC_FILES := $(wildcard $(SRC_DIR)/*.c)

XDP_OBJ_FILES := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/xdp_%.o, $(SRC_FILES))
TC_OBJ_FILES  := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/tc_%.o,  $(SRC_FILES))

XDP_ARGS := -DXDP_PROGRAM
TC_ARGS  := -DTC_PROGRAM

all: xdp tc

$(OBJ_DIR)/xdp_%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CLANG) $(CFLAGS) $(XDP_ARGS) -c $< -o $@

$(OBJ_DIR)/tc_%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CLANG) $(CFLAGS) $(TC_ARGS) -c $< -o $@

$(OBJ_DIR):
	@mkdir $(OBJ_DIR)

xdp: $(XDP_OBJ_FILES)

tc: $(TC_OBJ_FILES)

clean:
	@rm -rf $(OBJ_DIR)
