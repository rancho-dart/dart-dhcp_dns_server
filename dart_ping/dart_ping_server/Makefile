# Makefile for DART Ping Server (深度兼容方案)

# 核心配置区 ====================================================
SHELL := /bin/bash
.ONESHELL:  # 强制单Shell模式 (兼容GNU Make 3.82+)
.DEFAULT_GOAL := help  # 默认显示帮助信息
.PHONY: all clean install uninstall help

# 基础参数
EXEC_NAME      := dart-ping
SERVICE_NAME   := $(EXEC_NAME)
LOG_DIR        := /var/log

# 动态路径配置 (支持自定义覆盖)
INSTALL_DIR    ?= /usr/local/bin
CONFIG_DIR     ?= /etc/$(EXEC_NAME)

# 工具链配置 (支持交叉编译)
CC            := gcc
CFLAGS        := -g -Wall 
LIBS          := -lpcap
SETCAP_TOOL   := setcap

# 构建控制
BUILD_DEBUG   ?= 0  # 调试模式开关
ifeq ($(BUILD_DEBUG),1)
CFLAGS += -DDEBUG -O0
else
CFLAGS += -O2
endif

# 文件自动发现 ==================================================
SOURCE_FILES  := $(wildcard *.c)
OBJ_FILES     := $(patsubst %.c,%.o,$(SOURCE_FILES))

# 多平台兼容处理 ================================================
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Windows_NT)
RM       := del /Q
SERVICE_DIR := "C:/Windows/System32"
else
RM       := rm -f
SERVICE_DIR := /etc/systemd/system
endif

# 构建规则 =====================================================
all: $(EXEC_NAME)

$(EXEC_NAME): $(OBJ_FILES)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 安装部署规则 =================================================
install: $(EXEC_NAME)
	@echo ">> 安装二进制文件到系统目录"
	sudo install -m 0755 $(EXEC_NAME) $(INSTALL_DIR)/$(EXEC_NAME)
	sudo $(SETCAP_TOOL) cap_net_raw,cap_net_admin+ep $(INSTALL_DIR)/$(EXEC_NAME)

	@echo ">> 生成Systemd服务文件"
	sudo bash -c 'printf "%s\n" \
	"[Unit]" \
	"Description=DART Protocol Ping Service" \
	"After=network.target" \
	"" \
	"[Service]" \
	"Type=simple" \
	"ExecStart=$(INSTALL_DIR)/$(EXEC_NAME)" \
	"Restart=always" \
	"RestartSec=5" \
	"StandardOutput=syslog" \
	"StandardError=syslog" \
	"SyslogIdentifier=$(SERVICE_NAME)" \
	"" \
	"[Install]" \
	"WantedBy=multi-user.target" \
	> $(SERVICE_DIR)/$(SERVICE_NAME).service'

	@echo ">> 配置日志系统"
	sudo bash -c 'echo "if \$$programname == '\''$(SERVICE_NAME)'\'' then $(LOG_DIR)/$(SERVICE_NAME).log" > /etc/rsyslog.d/30-$(SERVICE_NAME).conf'
	sudo bash -c 'echo "& stop" >> /etc/rsyslog.d/30-$(SERVICE_NAME).conf'

	@echo ">> 重载系统服务"
	sudo systemctl daemon-reload
	sudo systemctl restart rsyslog

# 清理规则 =====================================================
clean:
	$(RM) $(EXEC_NAME) $(OBJ_FILES)

uninstall:
	@echo ">> 移除系统服务"
	-sudo systemctl stop $(SERVICE_NAME)
	-sudo systemctl disable $(SERVICE_NAME)
	sudo $(RM) $(INSTALL_DIR)/$(EXEC_NAME)
	sudo $(RM) $(SERVICE_DIR)/$(SERVICE_NAME).service
	sudo $(RM) /etc/rsyslog.d/30-$(SERVICE_NAME).conf
	sudo $(RM) /etc/logrotate.d/$(SERVICE_NAME)
	sudo systemctl daemon-reload

# 帮助信息 =====================================================
help:
	@echo "可用命令:"
	@echo "  make all          - 编译程序 (默认)"
	@echo "  make install      - 安装为系统服务"
	@echo "  make uninstall    - 卸载服务"
	@echo "  make clean        - 清理编译产物"
	@echo ""
	@echo "环境变量覆盖示例:"
	@echo "  INSTALL_DIR=/custom/path make install"
	@echo "  BUILD_DEBUG=1 make"