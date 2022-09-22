pub const ADD_EAX_IMM32: u8 = 0x05;
pub const RM32_IMM32: u8 = 0x81;
pub const ADD_RM32_R32: u8 = 0x01;
pub const ADD_R32_RM32: u8 = 0x03;

pub const AND_EAX_IMM32: u8 = 0x25;
pub const AND_RM32_R32: u8 = 0x21;
pub const AND_R32_RM32: u8 = 0x23;

pub const CALL_REL32: u8 = 0xE8;
pub const CALL_RM32: u8 = 0xFF;

pub const CLFLUSH_0: u8 = 0x0F;
pub const CLFLUSH_1: u8 = 0xAE;

pub const CMP_EAX_IMM32: u8 = 0x3D;
pub const CMP_RM32_R32: u8 = 0x39;
pub const CMP_R32_RM32: u8 = 0x3B;

pub const DEC_INC_PUSH_RM32: u8 = 0xFF;
pub const DEC_BASE: u8 = 0x48;
pub const DEC_LIMIT: u8 = DEC_BASE + 7;

pub const IDIV_NOT_TEST_RM32: u8 = 0xF7;

pub const INC_BASE: u8 = 0x40;
pub const INC_LIMIT: u8 = INC_BASE + 7;

pub const JMP_REL8: u8 = 0xEB;
pub const JMP_REL32: u8 = 0xE9;
pub const JMP_RM32: u8 = 0xFF;

pub const JZ_REL8: u8 = 0x74;
pub const COND_JMP_REL32_0: u8 = 0x0F;
pub const JZ_REL32_1: u8 = 0x84;
pub const JNZ_REL8: u8 = 0x75;
pub const JNZ_REL32_1: u8 = 0x85;

pub const LEA_R32: u8 = 0x8D;

pub const MOV_EAX_MOFFS32: u8 = 0xA1;
pub const MOV_MOFFS32_EAX: u8 = 0xA3;
pub const MOV_R32_IMM32_BASE: u8 = 0xB8;
pub const MOV_R32_IMM32_LIMIT: u8 = MOV_R32_IMM32_BASE + 7;
pub const MOV_RM32_IMM32: u8 = 0xC7;
pub const MOV_RM32_R32: u8 = 0x89;
pub const MOV_R32_RM32: u8 = 0x8B;

pub const MOVSD: u8 = 0xA5;

pub const NOP: u8 = 0x90;

pub const OR_EAX_IMM32: u8 = 0x0D;
pub const OR_RM32_R32: u8 = 0x09;
pub const OR_R32_RM32: u8 = 0x0B;

pub const POP_RM32: u8 = 0x8F;
pub const POP_BASE: u8 = 0x58;
pub const POP_LIMIT: u8 = POP_BASE + 7;

pub const PUSH_BASE: u8 = 0x50;
pub const PUSH_LIMIT: u8 = PUSH_BASE + 7;
pub const PUSH_IMM: u8 = 0x68;

pub const REPNE_CMPSD_0: u8 = 0xF2;
pub const REPNE_CMPSD_1: u8 = 0xA7;

pub const RETF: u8 = 0xCB;
pub const RETF_IMM16: u8 = 0xCA;
pub const RETN: u8 = 0xC3;
pub const RETN_IMM16: u8 = 0xC2;

pub const SUB_EAX_IMM32: u8 = 0x2D;
pub const SUB_RM32_R32: u8 = 0x29;
pub const SUB_R32_RM32: u8 = 0x2B;

pub const TEST_EAX_IMM32: u8 = 0xA9;
pub const TEST_R32_RM32: u8 = 0x85;

pub const XOR_EAX_IMM32: u8 = 0x35;
pub const XOR_RM32_R32: u8 = 0x31;
pub const XOR_R32_RM32: u8 = 0x33;
