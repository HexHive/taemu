CFG_TEE_TA_LOG_LEVEL ?= 0

# UUID is provided on the command line via BINARY=
BINARY ?= 11111111-1111-1111-1111-111111111111

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
clean:
	@echo 'Note: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk not found, cannot clean TA'
endif
