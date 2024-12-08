SUBDIRS := bpfw flowtrack

define foreach_subdirs
	@$(foreach dir,$(SUBDIRS), \
		echo -e "\n$(1) $(dir):"; \
		$(MAKE) -C $(dir) $(2);)
endef

all:
	$(call foreach_subdirs,"Building")

clean:
	$(call foreach_subdirs,"Cleaning",clean)
