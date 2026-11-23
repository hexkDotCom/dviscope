# SPDX-License-Identifier: Apache-2.0
# Builds selfcheck.elf with the Ibex simple system's common files:
#   make -C corpus/designs/ibex/selfcheck IBEX={ibex checkout} OUT={build dir}
IBEX ?= $(error set IBEX to the Ibex checkout)
OUT ?= .
CC = riscv64-unknown-elf-gcc
COMMON = $(IBEX)/examples/sw/simple_system/common
CFLAGS = -march=rv32imc_zicsr -mabi=ilp32 -static -mcmodel=medany -Wall -Werror -O1 \
         -fvisibility=hidden -nostdlib -nostartfiles -ffreestanding -I$(COMMON)

$(OUT)/selfcheck.elf: selfcheck.c $(COMMON)/simple_system_common.c $(COMMON)/crt0.S $(COMMON)/link.ld
	$(CC) $(CFLAGS) -T $(COMMON)/link.ld -Wl,--no-warn-rwx-segments \
	   selfcheck.c $(COMMON)/simple_system_common.c $(COMMON)/crt0.S -o $@ -lgcc
