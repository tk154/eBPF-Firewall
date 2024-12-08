define make_subdir
	@echo -e "\n$(1):"
	@$(MAKE) -C $(2) $(3)
endef

define build_subdir
	$(call make_subdir,"Building $(1)",$(2))
endef

define clean_subdir
	$(call make_subdir,"Cleaning $(1)",$(2),clean)
endef

all:
	$(call build_subdir,"eBPF objects",kernel)
	$(call build_subdir,"user-space programs",user)

clean:
	$(call clean_subdir,"eBPF objects",kernel)
	$(call clean_subdir,"user-space programs",user)
