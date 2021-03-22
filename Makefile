TARGET := iphone:clang:latest:7.0

include $(THEOS)/makefiles/common.mk

TOOL_NAME = harlogger

harlogger_FILES = main.m
harlogger_CFLAGS = -fobjc-arc
harlogger_CODESIGN_FLAGS = -Sentitlements.plist
harlogger_INSTALL_PATH = /usr/local/bin

include $(THEOS_MAKE_PATH)/tool.mk
