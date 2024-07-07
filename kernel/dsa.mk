BPF_DSA_NAME := $(BPF_NAME)_dsa
DSA_DRIVERS := gswip mtk qca

dsa: $(DSA_DRIVERS)

define GENERATE_RULES
DSA_DRIVER := $(shell echo $(1) | tr '[:lower:]' '[:upper:]')
DSA_FLAGS  := -DBPFW_DSA -DDSA_$$(DSA_DRIVER)

XDP_LE_OBJ_FILE := $(OBJ_DIR)/xdp_le_$(1)_$(BPF_DSA_NAME).o
XDP_BE_OBJ_FILE := $(OBJ_DIR)/xdp_be_$(1)_$(BPF_DSA_NAME).o
TC_LE_OBJ_FILE  := $(OBJ_DIR)/tc_le_$(1)_$(BPF_DSA_NAME).o
TC_BE_OBJ_FILE  := $(OBJ_DIR)/tc_be_$(1)_$(BPF_DSA_NAME).o

$(1): $(1)-xdp-le $(1)-tc-le $(1)-xdp-be $(1)-tc-be

$(1)-xdp: $(1)-xdp-le $(1)-xdp-be
$(1)-tc:  $(1)-tc-le  $(1)-tc-be
$(1)-le:  $(1)-xdp-le $(1)-tc-le
$(1)-be:  $(1)-xdp-be $(1)-tc-be

$(1)-xdp-le: $$(XDP_LE_OBJ_FILE)
$(1)-tc-le:  $$(TC_LE_OBJ_FILE)
$(1)-xdp-be: $$(XDP_BE_OBJ_FILE)
$(1)-tc-be:  $$(TC_BE_OBJ_FILE)

$(call BPF_COMPILE,$$(XDP_LE_OBJ_FILE),$(LE_FLAGS) $(XDP_FLAGS) $(OPTIONS) $$(DSA_FLAGS))
$(call BPF_COMPILE,$$(XDP_BE_OBJ_FILE),$(BE_FLAGS) $(XDP_FLAGS) $(OPTIONS) $$(DSA_FLAGS))
$(call BPF_COMPILE,$$(TC_LE_OBJ_FILE),$(LE_FLAGS) $(TC_FLAGS) $(OPTIONS) $$(DSA_FLAGS))
$(call BPF_COMPILE,$$(TC_BE_OBJ_FILE),$(BE_FLAGS) $(TC_FLAGS) $(OPTIONS) $$(DSA_FLAGS))
endef

$(foreach driver,$(DSA_DRIVERS),$(eval $(call GENERATE_RULES,$(driver))))
