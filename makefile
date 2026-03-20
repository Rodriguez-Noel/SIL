ROOT := $(CURDIR)

CC := gcc
CFLAGS := -O2 -g -Wall -Wextra
GO := go
CLANG := clang

HOST_TRIPLE := $(shell gcc -dumpmachine)
ARCH_INCLUDE_DIR := /usr/include/$(HOST_TRIPLE)

CGM_UTIL_DIR := ./utils/control_group_monitoring
PS_UTIL_DIR := ./utils/process_snapshot
OPT_DIR := ./opt
DP_DIR := ./orc/dp
CLI_DIR := ./orc/cli
TUI_DIR := ./orc/tui

STAGING_BIN := ./staging/bin
STAGING_OBJ := ./staging/obj

CGM_BIN_DIR := $(STAGING_BIN)/utils/control_group_monitoring
PS_BIN_DIR := $(STAGING_BIN)/utils/process_snapshot
OPT_BIN_DIR := $(STAGING_BIN)/opt
DP_BIN_DIR := $(STAGING_BIN)/orc/dp
CLI_BIN_DIR := $(STAGING_BIN)/orc/cli
TUI_BIN_DIR := $(STAGING_BIN)/orc/tui

CGM_OBJ_DIR := $(STAGING_OBJ)/utils/control_group_monitoring
PS_OBJ_DIR := $(STAGING_OBJ)/utils/process_snapshot
OPT_OBJ_DIR := $(STAGING_OBJ)/opt
BPF_OBJ_DIR := $(STAGING_OBJ)/bpf

CGM_LIB_O := $(CGM_OBJ_DIR)/CGM_LIB.o
CGM_SETUP_O := $(CGM_OBJ_DIR)/SIL_CGM_SETUP.o
CGM_ATTACH_O := $(CGM_OBJ_DIR)/SIL_CGM_ATTACH.o
CGM_LD_O := $(CGM_OBJ_DIR)/SIL_CGM_LD.o
CGM_ST_O := $(CGM_OBJ_DIR)/SIL_CGM_ST.o
CGM_OPT_O := $(OPT_OBJ_DIR)/SIL_CGM_opt.o

PS_LD_O := $(PS_OBJ_DIR)/SIL_PS_LD.o
PS_ST_O := $(PS_OBJ_DIR)/SIL_PS_ST.o
PS_OPT_O := $(OPT_OBJ_DIR)/SIL_PS_opt.o

CGM_SETUP_BIN := $(CGM_BIN_DIR)/SIL_CGM_SETUP
CGM_ATTACH_BIN := $(CGM_BIN_DIR)/SIL_CGM_ATTACH
CGM_LD_BIN := $(CGM_BIN_DIR)/SIL_CGM_LD
CGM_ST_BIN := $(CGM_BIN_DIR)/SIL_CGM_ST
CGM_OPT_BIN := $(OPT_BIN_DIR)/SIL_CGM_opt

PS_LD_BIN := $(PS_BIN_DIR)/SIL_PS_LD
PS_ST_BIN := $(PS_BIN_DIR)/SIL_PS_ST
PS_OPT_BIN := $(OPT_BIN_DIR)/SIL_PS_opt

DP_BIN := $(DP_BIN_DIR)/SIL_DP_O
CLI_BIN := $(CLI_BIN_DIR)/SIL_CLI_UI
TUI_BIN := $(TUI_BIN_DIR)/SIL_TUI_UI

BPF_OBJ := $(BPF_OBJ_DIR)/CGM.bpf.o
BPF_SKEL := $(BPF_OBJ_DIR)/CGM.skel.h

INCLUDES_CGM := -I$(CGM_UTIL_DIR) -I./bpf -I$(BPF_OBJ_DIR)
INCLUDES_PS := -I$(PS_UTIL_DIR)
INCLUDES_OPT := -I$(OPT_DIR)

BPF_CFLAGS := -O2 -g -target bpf -I$(ARCH_INCLUDE_DIR)

LIBBPF_LINK := -lbpf -lelf -lz

.PHONY: all init dirs clean distclean reset-runtime reset-pins \
	cgm ps opt dp cli tui orc test test-root

all: dirs cgm ps opt dp cli tui

init:
	./setup_sil.sh init

dirs:
	mkdir -p $(CGM_BIN_DIR) $(PS_BIN_DIR) $(OPT_BIN_DIR)
	mkdir -p $(DP_BIN_DIR) $(CLI_BIN_DIR) $(TUI_BIN_DIR)
	mkdir -p $(CGM_OBJ_DIR) $(PS_OBJ_DIR) $(OPT_OBJ_DIR) $(BPF_OBJ_DIR)
	mkdir -p ./data/cgm ./data/ps ./data/logs ./data/instances ./data/tmp

# ----------------------------- BPF / CGM -------------------------------- #

$(BPF_OBJ): ./bpf/CGM.bpf.c ./bpf/CGM.bpf.h | dirs
	$(CLANG) $(BPF_CFLAGS) -c ./bpf/CGM.bpf.c -o $(BPF_OBJ)

$(BPF_SKEL): $(BPF_OBJ) | dirs
	bpftool gen skeleton $(BPF_OBJ) > $(BPF_SKEL)

$(CGM_LIB_O): $(CGM_UTIL_DIR)/CGM_LIB.c $(CGM_UTIL_DIR)/CGM.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES_CGM) -c $< -o $@

$(CGM_SETUP_O): $(CGM_UTIL_DIR)/SIL_CGM_SETUP.c $(CGM_UTIL_DIR)/CGM.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES_CGM) -c $< -o $@

$(CGM_ATTACH_O): $(CGM_UTIL_DIR)/SIL_CGM_ATTACH.c $(CGM_UTIL_DIR)/CGM.h $(BPF_SKEL) ./bpf/CGM.bpf.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES_CGM) -c $< -o $@

$(CGM_LD_O): $(CGM_UTIL_DIR)/SIL_CGM_LD.c $(CGM_UTIL_DIR)/CGM.h ./bpf/CGM.bpf.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES_CGM) -c $< -o $@

$(CGM_ST_O): $(CGM_UTIL_DIR)/SIL_CGM_ST.c $(CGM_UTIL_DIR)/CGM.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES_CGM) -c $< -o $@

$(CGM_OPT_O): $(OPT_DIR)/SIL_CGM_opt.c $(OPT_DIR)/OPT.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES_OPT) -c $< -o $@

$(CGM_SETUP_BIN): $(CGM_SETUP_O) $(CGM_LIB_O)
	$(CC) $(CFLAGS) $^ -o $@

$(CGM_ATTACH_BIN): $(CGM_ATTACH_O) $(CGM_LIB_O)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBBPF_LINK)

$(CGM_LD_BIN): $(CGM_LD_O)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBBPF_LINK)

$(CGM_ST_BIN): $(CGM_ST_O)
	$(CC) $(CFLAGS) $^ -o $@

$(CGM_OPT_BIN): $(CGM_OPT_O)
	$(CC) $(CFLAGS) $^ -o $@

cgm: $(CGM_SETUP_BIN) $(CGM_ATTACH_BIN) $(CGM_LD_BIN) $(CGM_ST_BIN) $(CGM_OPT_BIN)

# --------------------------- Process Snapshot ----------------------------- #

$(PS_LD_O): $(PS_UTIL_DIR)/SIL_PS_LD.c $(PS_UTIL_DIR)/PS.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES_PS) -c $< -o $@

$(PS_ST_O): $(PS_UTIL_DIR)/SIL_PS_ST.c $(PS_UTIL_DIR)/PS.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES_PS) -c $< -o $@

$(PS_OPT_O): $(OPT_DIR)/SIL_PS_opt.c $(OPT_DIR)/OPT.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES_OPT) -c $< -o $@

$(PS_LD_BIN): $(PS_LD_O)
	$(CC) $(CFLAGS) $^ -o $@

$(PS_ST_BIN): $(PS_ST_O)
	$(CC) $(CFLAGS) $^ -o $@

$(PS_OPT_BIN): $(PS_OPT_O)
	$(CC) $(CFLAGS) $^ -o $@

ps: $(PS_LD_BIN) $(PS_ST_BIN)
opt: $(PS_OPT_BIN) $(CGM_OPT_BIN)

# ---------------------------- Orchestration ------------------------------- #

dp:
	$(GO) build -o $(DP_BIN) ./orc/dp/*.go

cli:
	$(GO) build -o $(CLI_BIN) ./orc/cli/SIL_CLI_UI.go

tui:
	$(GO) build -o $(TUI_BIN) ./orc/tui/SIL_TUI_UI.go

orc: dp cli tui

# ------------------------------ Cleanup ---------------------------------- #

reset-runtime:
	./setup_sil.sh reset-runtime

reset-pins:
	sudo ./setup_sil.sh reset-pins

clean:
	rm -f $(CGM_OBJ_DIR)/*.o
	rm -f $(PS_OBJ_DIR)/*.o
	rm -f $(OPT_OBJ_DIR)/*.o
	rm -f $(BPF_OBJ_DIR)/*.o
	rm -f $(BPF_SKEL)
	rm -f $(CGM_BIN_DIR)/*
	rm -f $(PS_BIN_DIR)/*
	rm -f $(OPT_BIN_DIR)/*
	rm -f $(DP_BIN_DIR)/*
	rm -f $(CLI_BIN_DIR)/*
	rm -f $(TUI_BIN_DIR)/*

distclean: clean
	rm -rf ./data/instances
	rm -rf ./data/tmp
