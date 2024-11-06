#!/usr/bin/python3

import math
import logging
from pwn import *
from unicorn import *
from capstone import *
from unicorn.rh850_const import *


# code flash 0x00000000~0x001fffff
code_flash=[
    # 0
    [0x00000000,0x00001fff], # 8k
    [0x00002000,0x00003fff],  # 8k
    # ...
    [0x0000e000,0x0000ffff],  # 8k
    [0x001f8000,0x001fffff]  # 8k
    # 20000000
]


# Memory map
# BOOT_ADDRESS  = 0x00000000
# BOOT_LEN      = 0x0001ffff # 128k
# CALIB_ADDRESS = 0x0000A000
CODE_ADDRESS        = 0x00000000
CODE_LEN            = 0x0FFFFFFF
LOCAL_RAM_ADDRESS   = 0xFE800000
LOCAL_RAM_LEN       = 0x00400000
GLOBAL_RAM_ADDRESS  = 0xFEE00000
GLOBAL_RAM_LEN      = 0x01200000
STACK_ADDRESS       = 0x60000000
STACK_LEN           = 0x00010000

EMU_ADDRESS = 0x00000e60
EMU_END_ADDRESS = 0x00000f28

UDS_PAYLOAD   = b'\x22\xF2\xAA'

def define_memory_size(size):
    if size % 4096 != 0:
        size = math.ceil(size/4096)*4096
    return size

# def hook_code(uc, address, size, user_data):
    # print(">>>Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))

def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))

def hook_code(uc, address, size, user_data):
    bytes_per_line = 4
    line_count = int(size / bytes_per_line)
    for cur_line_idx in range(line_count):
        start_address = address + cur_line_idx * bytes_per_line
        code_offset = start_address - CODE_ADDRESS
        opcode_bytes = uc.mem_read(start_address, bytes_per_line)
        opcode_byte_str = ''.join('{:02X} '.format(each_byte) for each_byte in opcode_bytes)
        decoded_insn_generator = uc.disasm(opcode_bytes, start_address)
        for each_decoded_insn in decoded_insn_generator:
            each_instruction_name = each_decoded_insn.mnemonic
            offset_str = "<+%d>" % code_offset
            print("--- 0x%08X %7s: %s -> %s\t%s" % (start_address, offset_str, opcode_byte_str, each_instruction_name, each_decoded_insn.op_str))


if __name__ == "__main__":
    # logging.basicConfig()
    try:
        uc = Uc(UC_ARCH_RH850, UC_MODE_LITTLE_ENDIAN)

        #../../samples/cybersecure_001_001_AppBoot.hex
        with open("../../samples/output.bin","rb") as f:
            app = f.read()
            f.close()
            print(define_memory_size(len(app)),len(app))
            uc.mem_map(CODE_ADDRESS, define_memory_size(len(app)))
            uc.mem_write(CODE_ADDRESS, app)
            print(uc.mem_read(0x00017090,4))

        # Bootloader memory initialization
        # uc.mem_map(BOOT_ADDRESS, BOOT_LEN)

        # Stack initialization
        uc.mem_map(STACK_ADDRESS, STACK_LEN)
        uc.reg_write(UC_RH850_REG_SP, STACK_ADDRESS + STACK_LEN)

        # RAM initialization
        uc.mem_map(LOCAL_RAM_ADDRESS, LOCAL_RAM_LEN)
        uc.mem_map(GLOBAL_RAM_ADDRESS, GLOBAL_RAM_LEN)

        # Registers initialization
        uc.reg_write(UC_RH850_REG_PC, CODE_ADDRESS)

        # Emulate all the things
        uc.hook_add(UC_HOOK_CODE, hook_code)
        uc.hook_add(UC_HOOK_BLOCK, hook_block)

        #  timeout=0, count=0
        logging.info("Emulate RH850 code")
        # uc.emu_start(CODE_ADDRESS, CODE_ADDRESS + define_memory_size(CODE_LEN))
        uc.emu_start(EMU_ADDRESS, EMU_END_ADDRESS)
        logging.info(f"Starting emulation @{EMU_ADDRESS:#010x} to {EMU_END_ADDRESS:#010x}\n")
        logging.info(">>> Emulation done. Below is the CPU context")
        r1 = uc.reg_read(UC_RH850_REG_R1)
        r2 = uc.reg_read(UC_RH850_REG_R2)
        rlp = uc.reg_read(UC_RH850_REG_LP)
        r10 = uc.reg_read(UC_RH850_REG_R10)
        r29 = uc.reg_read(UC_RH850_REG_R29)
        print(">>> R1 = 0x%x" % r1)
        print(">>> R2 = 0x%x" % r2)
        print(">>> Rlp = 0x%x" % rlp)
        print(">>> R10 = 0x%x" % r10)
        print(">>> R29 = 0x%x" % r29)
        # uc.emu_stop()
    except unicorn.UcError as e:
        logging.error(f"Crash - Address : {uc.reg_read(UC_RH850_REG_PC):#08x}")
        logging.error(e)

"""
#define UC_RH850_SYSREG_SELID0   32
#define UC_RH850_SYSREG_SELID1   64
#define UC_RH850_SYSREG_SELID2   96
#define UC_RH850_SYSREG_SELID3   128
#define UC_RH850_SYSREG_SELID4   160
#define UC_RH850_SYSREG_SELID5   192
#define UC_RH850_SYSREG_SELID6   224
#define UC_RH850_SYSREG_SELID7   256

//> RH850 global purpose registers
typedef enum uc_rh850_reg {
    UC_RH850_REG_R0 = 0,
    UC_RH850_REG_R1,
    UC_RH850_REG_R2,
    UC_RH850_REG_R3,
    UC_RH850_REG_R4,
    UC_RH850_REG_R5,
    UC_RH850_REG_R6,
    UC_RH850_REG_R7,
    UC_RH850_REG_R8,
    UC_RH850_REG_R9,
    UC_RH850_REG_R10,
    UC_RH850_REG_R11,
    UC_RH850_REG_R12,
    UC_RH850_REG_R13,
    UC_RH850_REG_R14,
    UC_RH850_REG_R15,
    UC_RH850_REG_R16,
    UC_RH850_REG_R17,
    UC_RH850_REG_R18,
    UC_RH850_REG_R19,
    UC_RH850_REG_R20,
    UC_RH850_REG_R21,
    UC_RH850_REG_R22,
    UC_RH850_REG_R23,
    UC_RH850_REG_R24,
    UC_RH850_REG_R25,
    UC_RH850_REG_R26,
    UC_RH850_REG_R27,
    UC_RH850_REG_R28,
    UC_RH850_REG_R29,
    UC_RH850_REG_R30,
    UC_RH850_REG_R31,

    //> RH850 system registers, selection ID 0
    UC_RH850_REG_EIPC = UC_RH850_SYSREG_SELID0,
    UC_RH850_REG_EIPSW,
    UC_RH850_REG_FEPC,
    UC_RH850_REG_FEPSW,
    UC_RH850_REG_ECR,
    UC_RH850_REG_PSW,   (eflags)
    UC_RH850_REG_FPSR,
    UC_RH850_REG_FPEPC,
    UC_RH850_REG_FPST,
    UC_RH850_REG_FPCC,
    UC_RH850_REG_FPCFG,
    UC_RH850_REG_FPEC,
    UC_RH850_REG_EIIC = UC_RH850_SYSREG_SELID0 + 13,
    UC_RH850_REG_FEIC,
    UC_RH850_REG_CTPC = UC_RH850_SYSREG_SELID0 + 16,
    UC_RH850_REG_CTPSW,
    UC_RH850_REG_CTBP = UC_RH850_SYSREG_SELID0 + 20,
    UC_RH850_REG_EIWR = UC_RH850_SYSREG_SELID0 + 28,
    UC_RH850_REG_FEWR = UC_RH850_SYSREG_SELID0 + 29,
    UC_RH850_REG_BSEL = UC_RH850_SYSREG_SELID0 + 31,

    //> RH850 system regusters, selection ID 1
    UC_RH850_REG_MCFG0 = UC_RH850_SYSREG_SELID1,
    UC_RH850_REG_RBASE,
    UC_RH850_REG_EBASE,
    UC_RH850_REG_INTBP,
    UC_RH850_REG_MCTL,
    UC_RH850_REG_PID,
    UC_RH850_REG_SCCFG = UC_RH850_SYSREG_SELID1 + 11,
    UC_RH850_REG_SCBP,

    //> RH850 system registers, selection ID 2
    UC_RH850_REG_HTCFG0 = UC_RH850_SYSREG_SELID2,
    UC_RH850_REG_MEA = UC_RH850_SYSREG_SELID2 + 6,
    UC_RH850_REG_ASID,
    UC_RH850_REG_MEI,

    UC_RH850_REG_PC = UC_RH850_SYSREG_SELID7 + 32,  (PC)
    UC_RH850_REG_ENDING
} uc_cpu_rh850;

//> RH8509 Registers aliases.
#define UC_RH850_REG_ZERO        UC_RH850_REG_R0   (ZERO) 
#define UC_RH850_REG_SP          UC_RH850_REG_R3   (stack top)
#define UC_RH850_REG_EP          UC_RH850_REG_R30  (stack base)
#define UC_RH850_REG_LP          UC_RH850_REG_R31  (jmp LP)
"""