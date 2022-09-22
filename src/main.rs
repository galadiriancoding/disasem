#![deny(warnings)]
#![warn(
    clippy::all,
    //clippy::restriction,
    clippy::pedantic,
    clippy::nursery,
    //clippy::cargo,
)]
#![allow(clippy::use_self)]
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    convert::TryInto,
    error, fmt,
    fmt::Write,
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom},
    path::PathBuf,
    process,
};

use std::io::Write as IoWrite;

use clap::Parser;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

const ADD_EAX_IMM32: u8 = 0x05;
const RM32_IMM32: u8 = 0x81;
const ADD_RM32_R32: u8 = 0x01;
const ADD_R32_RM32: u8 = 0x03;

const AND_EAX_IMM32: u8 = 0x25;
const AND_RM32_R32: u8 = 0x21;
const AND_R32_RM32: u8 = 0x23;

const CALL_REL32: u8 = 0xe8;
const CALL_RM32: u8 = 0xff;

const CLFLUSH_0: u8 = 0x0f;
const CLFLUSH_1: u8 = 0xae;

const CMP_EAX_IMM32: u8 = 0x3d;
const CMP_RM32_R32: u8 = 0x39;
const CMP_R32_RM32: u8 = 0x3b;

const DEC_INC_PUSH_RM32: u8 = 0xff;
const DEC_BASE: u8 = 0x48;
const DEC_LIMIT: u8 = DEC_BASE + 7;

const IDIV_NOT_TEST_RM32: u8 = 0xf7;

const INC_BASE: u8 = 0x40;
const INC_LIMIT: u8 = INC_BASE + 7;

const JMP_REL8: u8 = 0xeb;
const JMP_REL32: u8 = 0xe9;
const JMP_RM32: u8 = 0xff;

const JZ_REL8: u8 = 0x74;
const COND_JMP_REL32_0: u8 = 0x0f;
const JZ_REL32_1: u8 = 0x84;
const JNZ_REL8: u8 = 0x75;
const JNZ_REL32_1: u8 = 0x85;

const LEA_R32: u8 = 0x8d;

const MOV_EAX_MOFFS32: u8 = 0xa1;
const MOV_MOFFS32_EAX: u8 = 0xa3;
const MOV_R32_IMM32_BASE: u8 = 0xb8;
const MOV_R32_IMM32_LIMIT: u8 = MOV_R32_IMM32_BASE + 7;
const MOV_RM32_R32: u8 = 0x89;
const MOV_R32_RM32: u8 = 0x8b;

const MOVSD: u8 = 0xa5;

const NOP: u8 = 0x90;

const OR_EAX_IMM32: u8 = 0x0d;
const OR_RM32_R32: u8 = 0x09;
const OR_R32_RM32: u8 = 0x0b;

const POP_RM32: u8 = 0x8f;
const POP_BASE: u8 = 0x58;
const POP_LIMIT: u8 = POP_BASE + 7;

const PUSH_BASE: u8 = 0x50;
const PUSH_LIMIT: u8 = PUSH_BASE + 7;
const PUSH_IMM: u8 = 0x68;

const REPNE_CMPSD_0: u8 = 0xf2;
const REPNE_CMPSD_1: u8 = 0xa7;

const RETF: u8 = 0xcb;
const RETF_IMM16: u8 = 0xca;
const RETN: u8 = 0xc3;
const RETN_IMM16: u8 = 0xc2;

const SUB_EAX_IMM32: u8 = 0x2d;
const SUB_RM32_R32: u8 = 0x29;
const SUB_R32_RM32: u8 = 0x2b;

const TEST_EAX_IMM32: u8 = 0xa9;
const TEST_R32_RM32: u8 = 0x85;

const XOR_EAX_IMM32: u8 = 0x35;
const XOR_RM32_R32: u8 = 0x31;
const XOR_R32_RM32: u8 = 0x33;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, value_parser, help = "Path to binary file to be disassembled")]
    input: PathBuf,

    #[clap(
        short,
        long,
        value_parser,
        help = "Use Linear Sweep (Recursive Descent is default)"
    )]
    linear: bool,
}

fn get_reader(args: &Args) -> Result<BufReader<File>, io::Error> {
    let file = File::open(&args.input)?;
    Ok(BufReader::new(file))
}

enum ExitErr {
    FileIO = 100,
    Algorithm = 101,
}

fn main() {
    let args = Args::parse();
    let mut reader = match get_reader(&args) {
        Ok(reader) => reader,
        Err(err) => {
            eprintln!("{}", err);
            process::exit(ExitErr::FileIO as i32);
        }
    };
    if let Err(err) = if args.linear {
        linear_sweep(&mut reader)
    } else {
        simplified_recursive_descent(&mut reader)
    } {
        eprintln!("{}", err);
        process::exit(ExitErr::Algorithm as i32);
    }
}

#[derive(Eq, Hash, PartialEq)]
enum Label {
    Offset(u32),
    Function(u32),
}

enum Deferred {
    Sentinal,
    Address(u32),
    Dummy,
}

struct AssemblyLine {
    opcode: &'static str,
    machine_code: String,
    operand_1: Option<Cow<'static, str>>,
    operand_2: Option<Cow<'static, str>>,
}

struct DisassemblerState {
    counter: u32,
    deferred_list: Vec<Deferred>,
    output_dict: HashMap<u32, AssemblyLine>,
    labels: HashSet<Label>,
    assembly_data: Vec<u8>,
}

impl DisassemblerState {
    fn new(reader: &mut BufReader<File>) -> Result<Self, io::Error> {
        let file_size = reader.seek(SeekFrom::End(0))?;
        if file_size > u64::from(u32::MAX) {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        #[allow(clippy::cast_possible_truncation)]
        let mut assembly_data = vec![0; file_size as usize];
        reader.seek(SeekFrom::Start(0))?;
        reader.read_exact(&mut assembly_data)?;
        Ok(Self {
            counter: 0,
            deferred_list: vec![Deferred::Sentinal],
            output_dict: HashMap::new(),
            labels: HashSet::new(),
            assembly_data,
        })
    }
}

fn linear_sweep(reader: &mut BufReader<File>) -> Result<(), Box<dyn error::Error>> {
    let mut state = DisassemblerState::new(reader)?;
    while (state.counter as usize) < state.assembly_data.len() {
        if !is_function_end(&mut state) {
            match is_call_inst(&mut state, false) {
                None => match is_jmp_inst(&mut state, false) {
                    None => disassemble_instruction(&mut state),
                    Some(_) => {}
                },
                Some(_) => {}
            }
        }
    }
    print_output_dict(&state)?;
    Ok(())
}

fn simplified_recursive_descent(reader: &mut BufReader<File>) -> Result<(), Box<dyn error::Error>> {
    let mut state = DisassemblerState::new(reader)?;
    loop {
        if state.counter as usize >= state.assembly_data.len() {
            print_output_dict(&state)?;
            break;
        }
        if state.output_dict.contains_key(&state.counter) || is_function_end(&mut state) {
            match state.deferred_list.pop().unwrap() {
                Deferred::Sentinal => {
                    print_output_dict(&state)?;
                    break;
                }
                Deferred::Address(addr) => {
                    state.counter = addr;
                    continue;
                }
                Deferred::Dummy => {}
            };
        } else {
            match is_call_inst(&mut state, true) {
                Some(call_info) => {
                    match call_info {
                        CallInfo::Followable(call_target) => {
                            state.deferred_list.push(Deferred::Address(state.counter));
                            state.counter = call_target;
                        }
                        CallInfo::Unfollowable => {
                            state.deferred_list.push(Deferred::Dummy);
                        }
                    }
                    continue;
                }
                None => match is_jmp_inst(&mut state, true) {
                    Some(jmp_type) => match jmp_type {
                        JmpInfo::Conditional(target) => {
                            state.deferred_list.push(Deferred::Address(target));
                        }
                        JmpInfo::Unconditional(target) => {
                            state.counter = target;
                        }
                        JmpInfo::Unfollowable => {}
                    },
                    None => {
                        disassemble_instruction(&mut state);
                    }
                },
            }
        }
    }
    Ok(())
}

fn print_output_dict(state: &DisassemblerState) -> Result<(), Box<dyn error::Error>> {
    let mut cursor: u32 = 0;
    let mut output = String::new();
    while (cursor as usize) < state.assembly_data.len() {
        if state.labels.contains(&Label::Function(cursor)) {
            writeln!(&mut output, "\nfunction_{:08x}h:", cursor)?;
        }
        if state.labels.contains(&Label::Offset(cursor)) {
            writeln!(&mut output, "\noffset_{:08x}h:", cursor)?;
        }
        match state.output_dict.get(&cursor) {
            None => {
                writeln!(
                    &mut output,
                    "{0:08X}: {1:02X}                       db {1:02x}",
                    cursor, state.assembly_data[cursor as usize]
                )?;
                cursor += 1;
            }
            Some(assem_line) => {
                writeln!(
                    &mut output,
                    "{:08X}: {:24} {} {}{}",
                    &cursor,
                    assem_line.machine_code,
                    assem_line.opcode,
                    match &assem_line.operand_1 {
                        None => "",
                        Some(op1) => op1,
                    },
                    match &assem_line.operand_2 {
                        None => Cow::Borrowed(""),
                        Some(op2) => Cow::Owned(format!(", {}", op2)),
                    }
                )?;
                let inst_len: u32 = (assem_line.machine_code.len() / 2).try_into().unwrap();
                cursor += inst_len;
            }
        }
    }
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    write!(handle, "{}", output)?;
    Ok(())
}

enum CallInfo {
    Followable(u32),
    Unfollowable,
}

fn is_call_inst(state: &mut DisassemblerState, check_target: bool) -> Option<CallInfo> {
    let cursor = state.counter as usize;
    if cursor >= state.assembly_data.len() {
        return None;
    }
    match *state.assembly_data.get(cursor).unwrap() {
        CALL_REL32 => {
            if cursor + 5 > state.assembly_data.len() {
                return None;
            }
            let offset = i32::from_le_bytes(
                state.assembly_data[cursor + 1..cursor + 5]
                    .try_into()
                    .unwrap(),
            );
            let next_inst = state.counter + 5;
            let target = if offset.is_negative() {
                next_inst.wrapping_sub(offset.unsigned_abs())
            } else {
                next_inst.wrapping_add(offset.unsigned_abs())
            };
            if target as usize >= state.assembly_data.len() && check_target {
                None
            } else {
                state.output_dict.insert(
                    state.counter,
                    AssemblyLine {
                        opcode: "call",
                        machine_code: byte_slice_to_hex_str(
                            &state.assembly_data[cursor..cursor + 5],
                        ),
                        operand_1: Some(Cow::Owned(format!("function_{:08x}h", target))),
                        operand_2: None,
                    },
                );
                state.labels.insert(Label::Function(target));
                state.counter += 5;
                Some(CallInfo::Followable(target))
            }
        }
        CALL_RM32 => {
            let mut bytes_needed = 0;
            match get_single_operand_from_digit(
                &state.assembly_data[cursor + 1..],
                2,
                &mut bytes_needed,
            ) {
                None => None,
                Some(op1) => {
                    bytes_needed += 1;
                    state.output_dict.insert(
                        state.counter,
                        AssemblyLine {
                            opcode: "call",
                            machine_code: byte_slice_to_hex_str(
                                &state.assembly_data[cursor..cursor + bytes_needed as usize],
                            ),
                            operand_1: Some(Cow::Owned(op1)),
                            operand_2: None,
                        },
                    );
                    state.counter += u32::from(bytes_needed);
                    Some(CallInfo::Unfollowable)
                }
            }
        }
        _ => None,
    }
}

fn is_function_end(state: &mut DisassemblerState) -> bool {
    let cursor: usize = state.counter as usize;
    if cursor >= state.assembly_data.len() {
        return false;
    }
    match *state.assembly_data.get(cursor).unwrap() {
        RETN => {
            state.output_dict.insert(
                state.counter,
                AssemblyLine {
                    opcode: "retn",
                    machine_code: "C3".to_owned(),
                    operand_1: None,
                    operand_2: None,
                },
            );
            state.counter += 1;
            true
        }
        RETF => {
            state.output_dict.insert(
                state.counter,
                AssemblyLine {
                    opcode: "retf",
                    machine_code: "CB".to_owned(),
                    operand_1: None,
                    operand_2: None,
                },
            );
            state.counter += 1;
            true
        }
        RETN_IMM16 => {
            if cursor + 3 > state.assembly_data.len() {
                return false;
            }
            let popval = u16::from_le_bytes(
                state.assembly_data[cursor + 1..cursor + 3]
                    .try_into()
                    .unwrap(),
            );

            state.output_dict.insert(
                state.counter,
                AssemblyLine {
                    opcode: "retn",
                    machine_code: byte_slice_to_hex_str(&state.assembly_data[cursor..cursor + 3]),
                    operand_1: Some(Cow::Owned(format!("{:#06x}", popval))),
                    operand_2: None,
                },
            );
            state.counter += 3;
            true
        }
        RETF_IMM16 => {
            if cursor + 3 > state.assembly_data.len() {
                return false;
            }
            let popval = u16::from_le_bytes(
                state.assembly_data[cursor + 1..cursor + 3]
                    .try_into()
                    .unwrap(),
            );

            state.output_dict.insert(
                state.counter,
                AssemblyLine {
                    opcode: "retf",
                    machine_code: byte_slice_to_hex_str(&state.assembly_data[cursor..cursor + 3]),
                    operand_1: Some(Cow::Owned(format!("{:#06x}", popval))),
                    operand_2: None,
                },
            );
            state.counter += 3;
            true
        }
        _ => false,
    }
}

fn byte_slice_to_hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

enum JmpInfo {
    Conditional(u32),
    Unconditional(u32),
    Unfollowable,
}

fn is_jmp_inst_jmp_rel8(state: &mut DisassemblerState, check_target: bool) -> Option<JmpInfo> {
    let cursor: usize = state.counter as usize;
    if cursor + 2 > state.assembly_data.len() {
        return None;
    }
    let relval = i8::from_le_bytes(
        state.assembly_data[cursor + 1..cursor + 2]
            .try_into()
            .unwrap(),
    );
    let target = {
        if relval.is_negative() {
            (state.counter + 2).wrapping_sub(u32::from(relval.unsigned_abs()))
        } else {
            (state.counter + 2).wrapping_add(u32::from(relval.unsigned_abs()))
        }
    };
    if target as usize >= state.assembly_data.len() && check_target {
        None
    } else {
        state.output_dict.insert(
            state.counter,
            AssemblyLine {
                opcode: "jmp",
                machine_code: byte_slice_to_hex_str(&state.assembly_data[cursor..cursor + 2]),
                operand_1: Some(Cow::Owned(format!("offset_{:08x}h", target))),
                operand_2: None,
            },
        );
        state.labels.insert(Label::Offset(target));
        state.counter += 2;
        Some(JmpInfo::Unconditional(target))
    }
}

fn is_jmp_inst_jmp_rel32(state: &mut DisassemblerState, check_target: bool) -> Option<JmpInfo> {
    let cursor: usize = state.counter as usize;
    if cursor + 5 > state.assembly_data.len() {
        return None;
    }
    let relval = i32::from_le_bytes(
        state.assembly_data[cursor + 1..cursor + 5]
            .try_into()
            .unwrap(),
    );
    let target = {
        if relval.is_negative() {
            (state.counter + 5).wrapping_sub(relval.unsigned_abs())
        } else {
            (state.counter + 5).wrapping_add(relval.unsigned_abs())
        }
    };
    if target as usize >= state.assembly_data.len() && check_target {
        None
    } else {
        state.output_dict.insert(
            state.counter,
            AssemblyLine {
                opcode: "jmp",
                machine_code: byte_slice_to_hex_str(&state.assembly_data[cursor..cursor + 5]),
                operand_1: Some(Cow::Owned(format!("offset_{:08x}h", target))),
                operand_2: None,
            },
        );
        state.labels.insert(Label::Offset(target));
        state.counter += 5;
        Some(JmpInfo::Unconditional(target))
    }
}

fn is_jmp_inst_jmp_rm32(state: &mut DisassemblerState) -> Option<JmpInfo> {
    let cursor: usize = state.counter as usize;
    let mut bytes_needed = 0;
    match get_single_operand_from_digit(&state.assembly_data[cursor + 1..], 4, &mut bytes_needed) {
        None => None,
        Some(op1) => {
            bytes_needed += 1;

            state.output_dict.insert(
                state.counter,
                AssemblyLine {
                    opcode: "jmp",
                    machine_code: byte_slice_to_hex_str(
                        &state.assembly_data[cursor..cursor + bytes_needed as usize],
                    ),
                    operand_1: Some(Cow::Owned(op1)),
                    operand_2: None,
                },
            );
            state.counter += u32::from(bytes_needed);
            Some(JmpInfo::Unfollowable)
        }
    }
}

fn is_jmp_inst_cond_jmp_rel32(
    state: &mut DisassemblerState,
    check_target: bool,
) -> Option<JmpInfo> {
    let cursor: usize = state.counter as usize;
    if cursor + 6 > state.assembly_data.len()
        || (state.assembly_data[cursor + 1] != JZ_REL32_1
            && state.assembly_data[cursor + 1] != JNZ_REL32_1)
    {
        return None;
    }
    let relval = i32::from_le_bytes(
        state.assembly_data[cursor + 2..cursor + 6]
            .try_into()
            .unwrap(),
    );
    let target = {
        if relval.is_negative() {
            (state.counter + 6).wrapping_sub(relval.unsigned_abs())
        } else {
            (state.counter + 6).wrapping_add(relval.unsigned_abs())
        }
    };
    if target as usize >= state.assembly_data.len() && check_target {
        None
    } else {
        state.output_dict.insert(
            state.counter,
            AssemblyLine {
                opcode: {
                    if state.assembly_data[cursor + 1] == JZ_REL32_1 {
                        "jz"
                    } else {
                        "jnz"
                    }
                },
                machine_code: byte_slice_to_hex_str(&state.assembly_data[cursor..cursor + 6]),
                operand_1: Some(Cow::Owned(format!("offset_{:08x}h", target))),
                operand_2: None,
            },
        );
        state.labels.insert(Label::Offset(target));
        state.counter += 6;
        Some(JmpInfo::Conditional(target))
    }
}

fn is_jmp_inst_cond_jmp_rel8(
    state: &mut DisassemblerState,
    check_target: bool,
    is_zero: bool,
) -> Option<JmpInfo> {
    let cursor: usize = state.counter as usize;
    if cursor + 2 > state.assembly_data.len() {
        return None;
    }
    let relval = i8::from_le_bytes(
        state.assembly_data[cursor + 1..cursor + 2]
            .try_into()
            .unwrap(),
    );
    let target = {
        if relval.is_negative() {
            (state.counter + 2).wrapping_sub(u32::from(relval.unsigned_abs()))
        } else {
            (state.counter + 2).wrapping_add(u32::from(relval.unsigned_abs()))
        }
    };
    if target as usize >= state.assembly_data.len() && check_target {
        None
    } else {
        state.output_dict.insert(
            state.counter,
            AssemblyLine {
                opcode: if is_zero { "jz" } else { "jnz" },
                machine_code: byte_slice_to_hex_str(&state.assembly_data[cursor..cursor + 2]),
                operand_1: Some(Cow::Owned(format!("offset_{:08x}h", target))),
                operand_2: None,
            },
        );
        state.labels.insert(Label::Offset(target));
        state.counter += 2;
        Some(JmpInfo::Conditional(target))
    }
}

fn is_jmp_inst(state: &mut DisassemblerState, check_target: bool) -> Option<JmpInfo> {
    let cursor: usize = state.counter as usize;
    if cursor + 1 > state.assembly_data.len() {
        return None;
    }
    match *state.assembly_data.get(cursor).unwrap() {
        JMP_REL8 => is_jmp_inst_jmp_rel8(state, check_target),
        JMP_REL32 => is_jmp_inst_jmp_rel32(state, check_target),
        JMP_RM32 => is_jmp_inst_jmp_rm32(state),
        JZ_REL8 => is_jmp_inst_cond_jmp_rel8(state, check_target, true),
        COND_JMP_REL32_0 => is_jmp_inst_cond_jmp_rel32(state, check_target),
        JNZ_REL8 => is_jmp_inst_cond_jmp_rel8(state, check_target, false),
        _ => None,
    }
}

fn disassemble_eax_imm32(state: &mut DisassemblerState, opcode: u8) {
    let inst_len = 5u32;
    let cursor = state.counter as usize;
    if cursor + inst_len as usize > state.assembly_data.len() {
        state.counter += 1;
    } else {
        let imm = i32::from_le_bytes(
            state.assembly_data[cursor + 1..cursor + inst_len as usize]
                .try_into()
                .unwrap(),
        );
        state.output_dict.insert(
            state.counter,
            AssemblyLine {
                opcode: match opcode {
                    ADD_EAX_IMM32 => "add",
                    AND_EAX_IMM32 => "and",
                    CMP_EAX_IMM32 => "cmp",
                    MOV_EAX_MOFFS32 => "mov",
                    OR_EAX_IMM32 => "or",
                    SUB_EAX_IMM32 => "sub",
                    TEST_EAX_IMM32 => "test",
                    XOR_EAX_IMM32 => "xor",
                    _ => {
                        state.counter += 1;
                        return;
                    }
                },
                machine_code: byte_slice_to_hex_str(
                    &state.assembly_data[cursor..cursor + inst_len as usize],
                ),
                operand_1: Some(Cow::Borrowed("eax")),
                operand_2: if opcode == MOV_EAX_MOFFS32 {
                    Some(Cow::Owned(format!("[{:#010x}]", imm,)))
                } else {
                    Some(Cow::Owned(format!(
                        "{}{:#010x}",
                        if imm.is_negative() { "-" } else { "" },
                        imm.unsigned_abs(),
                    )))
                },
            },
        );
        state.counter += inst_len;
    }
}

fn disassemble_rm32_imm32(state: &mut DisassemblerState) {
    let cursor = state.counter as usize;
    if cursor + 1 > state.assembly_data.len() {
        state.counter += 1;
    } else {
        let reg = ModRM::new(*state.assembly_data.get(cursor + 1).unwrap()).reg as u8;
        if reg == 2 || reg == 3 {
            state.counter += 1;
        } else {
            let mut bytes_read = 0;
            let op1 = get_single_operand_from_digit(
                &state.assembly_data[cursor + 1..],
                reg,
                &mut bytes_read,
            );
            match op1 {
                None => {
                    state.counter += 1;
                }
                Some(op1_str) => {
                    let inst_len = bytes_read + 5;
                    if cursor + inst_len as usize > state.assembly_data.len() {
                        state.counter += 1;
                    } else {
                        let imm = i32::from_le_bytes(
                            state.assembly_data
                                [cursor + 1 + bytes_read as usize..cursor + inst_len as usize]
                                .try_into()
                                .unwrap(),
                        );
                        let opcode = match reg {
                            0 => "add",
                            1 => "or",
                            4 => "and",
                            5 => "sub",
                            6 => "xor",
                            7 => "cmp",
                            _ => unreachable!(),
                        };
                        state.output_dict.insert(
                            state.counter,
                            AssemblyLine {
                                opcode,
                                machine_code: byte_slice_to_hex_str(
                                    &state.assembly_data[cursor..cursor + inst_len as usize],
                                ),
                                operand_1: Some(Cow::Owned(op1_str)),
                                operand_2: Some(Cow::Owned(format!(
                                    "{}{:#010x}",
                                    if imm.is_negative() { "-" } else { "" },
                                    imm.unsigned_abs()
                                ))),
                            },
                        );
                        state.counter += u32::from(inst_len);
                    }
                }
            }
        }
    }
}

fn disassemble_rm_reg(state: &mut DisassemblerState, opcode: u8) {
    let cursor = state.counter as usize;
    if cursor + 1 > state.assembly_data.len() {
        state.counter += 1;
    } else {
        let reg = ModRM::new(*state.assembly_data.get(cursor + 1).unwrap()).reg;
        let mut bytes_read = 0;
        let op1 = get_single_operand_from_digit(
            &state.assembly_data[cursor + 1..],
            reg as u8,
            &mut bytes_read,
        );
        match op1 {
            None => {
                state.counter += 1;
            }
            Some(op1_str) => {
                let inst_len = bytes_read + 1;
                if cursor + inst_len as usize > state.assembly_data.len() {
                    state.counter += 1;
                } else {
                    let opcode = match opcode {
                        ADD_RM32_R32 => "add",
                        AND_RM32_R32 => "and",
                        CMP_RM32_R32 => "cmp",
                        MOV_RM32_R32 => "mov",
                        OR_RM32_R32 => "or",
                        SUB_RM32_R32 => "sub",
                        TEST_R32_RM32 => "test",
                        XOR_RM32_R32 => "xor",
                        _ => {
                            state.counter += 1;
                            return;
                        }
                    };
                    state.output_dict.insert(
                        state.counter,
                        AssemblyLine {
                            opcode,
                            machine_code: byte_slice_to_hex_str(
                                &state.assembly_data[cursor..cursor + inst_len as usize],
                            ),
                            operand_1: Some(Cow::Owned(op1_str)),
                            operand_2: Some(Cow::Owned(reg.to_string())),
                        },
                    );
                    state.counter += u32::from(inst_len);
                }
            }
        }
    }
}

fn disassemble_reg_rm(state: &mut DisassemblerState, opcode: u8) {
    let cursor = state.counter as usize;
    if cursor + 1 > state.assembly_data.len() {
        state.counter += 1;
    } else {
        let reg = ModRM::new(*state.assembly_data.get(cursor + 1).unwrap()).reg;
        let mut bytes_read = 0;
        let op2 = get_single_operand_from_digit(
            &state.assembly_data[cursor + 1..],
            reg as u8,
            &mut bytes_read,
        );
        match op2 {
            None => {
                state.counter += 1;
            }
            Some(op2_str) => {
                let inst_len = bytes_read + 1;
                if cursor + inst_len as usize > state.assembly_data.len() {
                    state.counter += 1;
                } else {
                    let opcode = match opcode {
                        ADD_R32_RM32 => "add",
                        AND_R32_RM32 => "and",
                        CMP_R32_RM32 => "cmp",
                        MOV_R32_RM32 => "mov",
                        OR_R32_RM32 => "or",
                        SUB_R32_RM32 => "sub",
                        XOR_R32_RM32 => "xor",
                        _ => {
                            state.counter += 1;
                            return;
                        }
                    };
                    state.output_dict.insert(
                        state.counter,
                        AssemblyLine {
                            opcode,
                            machine_code: byte_slice_to_hex_str(
                                &state.assembly_data[cursor..cursor + inst_len as usize],
                            ),
                            operand_1: Some(Cow::Owned(reg.to_string())),
                            operand_2: Some(Cow::Owned(op2_str)),
                        },
                    );
                    state.counter += u32::from(inst_len);
                }
            }
        }
    }
}

fn disassemble_clflush(state: &mut DisassemblerState) {
    let cursor = state.counter as usize;
    if cursor + 2 > state.assembly_data.len()
        || *state.assembly_data.get(cursor + 1).unwrap() != CLFLUSH_1
    {
        state.counter += 1;
    } else {
        let mut bytes_read = 0;
        let op1 =
            get_single_operand_from_digit(&state.assembly_data[cursor + 2..], 7, &mut bytes_read);
        match op1 {
            None => {
                state.counter += 1;
            }
            Some(op1_str) => {
                if ModRM::new(*state.assembly_data.get(cursor + 1).unwrap()).adressing_mode
                    == AddressingMode::DirectAccess
                {
                    state.counter += 1;
                } else {
                    let inst_len = bytes_read + 2;
                    if cursor + inst_len as usize > state.assembly_data.len() {
                        state.counter += 1;
                    } else {
                        let opcode = "clflush";
                        state.output_dict.insert(
                            state.counter,
                            AssemblyLine {
                                opcode,
                                machine_code: byte_slice_to_hex_str(
                                    &state.assembly_data[cursor..cursor + inst_len as usize],
                                ),
                                operand_1: Some(Cow::Owned(op1_str)),
                                operand_2: None,
                            },
                        );
                        state.counter += u32::from(inst_len);
                    }
                }
            }
        }
    }
}

fn disassemble_dec_inc_push_rm32(state: &mut DisassemblerState) {
    let cursor = state.counter as usize;
    if cursor + 1 > state.assembly_data.len() {
        state.counter += 1;
    } else {
        let reg = ModRM::new(*state.assembly_data.get(cursor + 1).unwrap()).reg as u8;
        if reg == 2 || reg == 3 || reg == 4 || reg == 5 || reg == 7 {
            state.counter += 1;
        } else {
            let mut bytes_read = 0;
            let op1 = get_single_operand_from_digit(
                &state.assembly_data[cursor + 1..],
                reg,
                &mut bytes_read,
            );
            match op1 {
                None => {
                    state.counter += 1;
                }
                Some(op1_str) => {
                    let inst_len = bytes_read + 1;
                    if cursor + inst_len as usize > state.assembly_data.len() {
                        state.counter += 1;
                    } else {
                        let opcode = match reg {
                            0 => "inc",
                            1 => "dec",
                            6 => "push",
                            _ => unreachable!(),
                        };
                        state.output_dict.insert(
                            state.counter,
                            AssemblyLine {
                                opcode,
                                machine_code: byte_slice_to_hex_str(
                                    &state.assembly_data[cursor..cursor + inst_len as usize],
                                ),
                                operand_1: Some(Cow::Owned(op1_str)),
                                operand_2: None,
                            },
                        );
                        state.counter += u32::from(inst_len);
                    }
                }
            }
        }
    }
}

fn disassemble_plus_reg(state: &mut DisassemblerState, opcode: u8, base: u8, inst: &'static str) {
    if opcode - base > 7 {
        state.counter += 1;
        return;
    }
    let cursor = state.counter as usize;
    let inst_len = 1u32;
    if cursor + inst_len as usize > state.assembly_data.len() {
        state.counter += 1;
    } else {
        let reg: REG = FromPrimitive::from_u8(opcode - base).unwrap();
        state.output_dict.insert(
            state.counter,
            AssemblyLine {
                opcode: inst,
                machine_code: byte_slice_to_hex_str(
                    &state.assembly_data[cursor..cursor + inst_len as usize],
                ),
                operand_1: Some(Cow::Owned(reg.to_string())),
                operand_2: None,
            },
        );
        state.counter += inst_len;
    }
}

fn disassemble_idiv_not_test_rm32(state: &mut DisassemblerState) {
    let cursor = state.counter as usize;
    if cursor + 1 > state.assembly_data.len() {
        state.counter += 1;
    } else {
        let reg = ModRM::new(*state.assembly_data.get(cursor + 1).unwrap()).reg as u8;
        if reg == 1 || reg == 3 || reg == 4 || reg == 5 || reg == 6 {
            state.counter += 1;
        } else {
            let mut bytes_read = 0;
            let op1 = get_single_operand_from_digit(
                &state.assembly_data[cursor + 1..],
                reg,
                &mut bytes_read,
            );
            match op1 {
                None => {
                    state.counter += 1;
                }
                Some(op1_str) => {
                    let inst_len = if reg == 0 {
                        bytes_read + 5
                    } else {
                        bytes_read + 1
                    };
                    if cursor + inst_len as usize > state.assembly_data.len() {
                        state.counter += 1;
                    } else {
                        let opcode = match reg {
                            0 => "test",
                            2 => "not",
                            7 => "idiv",
                            _ => unreachable!(),
                        };
                        state.output_dict.insert(
                            state.counter,
                            AssemblyLine {
                                opcode,
                                machine_code: byte_slice_to_hex_str(
                                    &state.assembly_data[cursor..cursor + inst_len as usize],
                                ),
                                operand_1: Some(Cow::Owned(op1_str)),
                                operand_2: if reg == 0 {
                                    let imm = i32::from_le_bytes(
                                        state.assembly_data[cursor + 1 + bytes_read as usize
                                            ..cursor + inst_len as usize]
                                            .try_into()
                                            .unwrap(),
                                    );
                                    Some(Cow::Owned(format!(
                                        "{}{:#010x}",
                                        if imm.is_negative() { "-" } else { "" },
                                        imm
                                    )))
                                } else {
                                    None
                                },
                            },
                        );
                    }

                    state.counter += u32::from(inst_len);
                }
            }
        }
    }
}

fn disassemble_lea(state: &mut DisassemblerState) {
    let cursor = state.counter as usize;
    if cursor + 1 > state.assembly_data.len() {
        state.counter += 1;
    } else {
        let reg: REG = ModRM::new(*state.assembly_data.get(cursor + 1).unwrap()).reg;
        let mut bytes_read = 0;
        let op2 = get_single_operand_from_digit(
            &state.assembly_data[cursor + 1..],
            reg as u8,
            &mut bytes_read,
        );
        match op2 {
            None => {
                state.counter += 1;
            }
            Some(op2_str) => {
                if ModRM::new(*state.assembly_data.get(cursor + 1).unwrap()).adressing_mode
                    == AddressingMode::DirectAccess
                {
                    state.counter += 1;
                } else {
                    let inst_len = bytes_read + 1;
                    if cursor + inst_len as usize > state.assembly_data.len() {
                        state.counter += 1;
                    } else {
                        let opcode = "lea";
                        state.output_dict.insert(
                            state.counter,
                            AssemblyLine {
                                opcode,
                                machine_code: byte_slice_to_hex_str(
                                    &state.assembly_data[cursor..cursor + inst_len as usize],
                                ),
                                operand_1: Some(Cow::Owned(reg.to_string())),
                                operand_2: Some(Cow::Owned(op2_str)),
                            },
                        );
                        state.counter += u32::from(inst_len);
                    }
                }
            }
        }
    }
}

fn disassemble_mov_moffs32_eax(state: &mut DisassemblerState) {
    let cursor = state.counter as usize;
    if cursor + 5 > state.assembly_data.len() {
        state.counter += 1;
    } else {
        let inst_len = 5u32;
        let imm = u32::from_le_bytes(
            state.assembly_data[cursor + 1..cursor + 5]
                .try_into()
                .unwrap(),
        );
        state.output_dict.insert(
            state.counter,
            AssemblyLine {
                opcode: "mov",
                machine_code: byte_slice_to_hex_str(
                    &state.assembly_data[cursor..cursor + inst_len as usize],
                ),
                operand_1: Some(Cow::Owned(format!("[{:#010x}]", imm))),
                operand_2: Some(Cow::Borrowed("eax")),
            },
        );
        state.counter += inst_len;
    }
}

fn disassemble_mov_r32_imm32(state: &mut DisassemblerState, opcode: u8) {
    let cursor = state.counter as usize;
    if (opcode - MOV_R32_IMM32_BASE) > 7 {
        state.counter += 1;
        return;
    }
    if cursor + 5 > state.assembly_data.len() {
        state.counter += 1;
    } else {
        let inst_len = 5u32;
        let imm = i32::from_le_bytes(
            state.assembly_data[cursor + 1..cursor + 5]
                .try_into()
                .unwrap(),
        );
        let reg: REG = FromPrimitive::from_u8(opcode - MOV_R32_IMM32_BASE).unwrap();
        state.output_dict.insert(
            state.counter,
            AssemblyLine {
                opcode: "mov",
                machine_code: byte_slice_to_hex_str(
                    &state.assembly_data[cursor..cursor + inst_len as usize],
                ),
                operand_1: Some(Cow::Owned(reg.to_string())),
                operand_2: Some(Cow::Owned(format!(
                    "{}{:#010x}",
                    if imm.is_negative() { "-" } else { "" },
                    imm
                ))),
            },
        );
        state.counter += inst_len;
    }
}

fn disassemble_mov_rm32_imm32(state: &mut DisassemblerState) {
    let cursor = state.counter as usize;
    if cursor + 6 > state.assembly_data.len() {
        state.counter += 1;
    } else {
        let mut bytes_read = 0;
        let op1 =
            get_single_operand_from_digit(&state.assembly_data[cursor + 1..], 0, &mut bytes_read);
        match op1 {
            None => {
                state.counter += 1;
            }
            Some(op1_str) => {
                let inst_len = bytes_read + 1 + 4;
                if cursor + inst_len as usize > state.assembly_data.len() {
                    state.counter += 1;
                } else {
                    let imm = i32::from_le_bytes(
                        state.assembly_data
                            [cursor + 1 + bytes_read as usize..cursor + inst_len as usize]
                            .try_into()
                            .unwrap(),
                    );
                    state.output_dict.insert(
                        state.counter,
                        AssemblyLine {
                            opcode: "mov",
                            machine_code: byte_slice_to_hex_str(
                                &state.assembly_data[cursor..cursor + inst_len as usize],
                            ),
                            operand_1: Some(Cow::Owned(op1_str)),
                            operand_2: Some(Cow::Owned(format!(
                                "{}{:#010x}",
                                if imm.is_negative() { "-" } else { "" },
                                imm
                            ))),
                        },
                    );
                    state.counter += u32::from(inst_len);
                }
            }
        }
    }
}

fn disassemble_movsd(state: &mut DisassemblerState) {
    let cursor = state.counter as usize;
    let inst_len = 1u32;
    if cursor + inst_len as usize > state.assembly_data.len() {
        state.counter += 1;
    } else {
        state.output_dict.insert(
            state.counter,
            AssemblyLine {
                opcode: "movsd",
                machine_code: byte_slice_to_hex_str(
                    &state.assembly_data[cursor..cursor + inst_len as usize],
                ),
                operand_1: Some(Cow::Borrowed("[edi]")),
                operand_2: Some(Cow::Borrowed("[esi]")),
            },
        );
        state.counter += inst_len;
    }
}

fn disassemble_nop(state: &mut DisassemblerState) {
    let cursor = state.counter as usize;
    let inst_len = 1u32;
    if cursor + inst_len as usize > state.assembly_data.len() {
        state.counter += 1;
    } else {
        state.output_dict.insert(
            state.counter,
            AssemblyLine {
                opcode: "nop",
                machine_code: byte_slice_to_hex_str(
                    &state.assembly_data[cursor..cursor + inst_len as usize],
                ),
                operand_1: None,
                operand_2: None,
            },
        );
        state.counter += inst_len;
    }
}

fn disassemble_pop_rm32(state: &mut DisassemblerState) {
    let cursor: usize = state.counter as usize;
    if cursor + 1 > state.assembly_data.len() {
        state.counter += 1;
    } else {
        let mut bytes_read = 0;
        let op1 =
            get_single_operand_from_digit(&state.assembly_data[cursor + 1..], 0, &mut bytes_read);
        match op1 {
            None => {
                state.counter += 1;
            }
            Some(op1_str) => {
                let inst_len = bytes_read + 1;
                if cursor + inst_len as usize > state.assembly_data.len() {
                    state.counter += 1;
                } else {
                    state.output_dict.insert(
                        state.counter,
                        AssemblyLine {
                            opcode: "pop",
                            machine_code: byte_slice_to_hex_str(
                                &state.assembly_data[cursor..cursor + inst_len as usize],
                            ),
                            operand_1: Some(Cow::Owned(op1_str)),
                            operand_2: None,
                        },
                    );
                    state.counter += u32::from(inst_len);
                }
            }
        }
    }
}

fn disassemble_push_imm(state: &mut DisassemblerState) {
    let cursor: usize = state.counter as usize;
    let inst_len = 5u32;
    if cursor + inst_len as usize > state.assembly_data.len() {
        state.counter += 1;
    } else {
        let imm = i32::from_le_bytes(
            state.assembly_data[cursor + 1..cursor + inst_len as usize]
                .try_into()
                .unwrap(),
        );
        state.output_dict.insert(
            state.counter,
            AssemblyLine {
                opcode: "push",
                machine_code: byte_slice_to_hex_str(
                    &state.assembly_data[cursor..cursor + inst_len as usize],
                ),
                operand_1: Some(Cow::Owned(format!(
                    "{}{:#010x}",
                    if imm.is_negative() { "-" } else { "" },
                    imm
                ))),
                operand_2: None,
            },
        );
        state.counter += inst_len;
    }
}

fn disassemble_repne_cmpsd(state: &mut DisassemblerState) {
    let cursor: usize = state.counter as usize;
    if cursor + 2 > state.assembly_data.len()
        || *state.assembly_data.get(cursor + 1).unwrap() != REPNE_CMPSD_1
    {
        state.counter += 1;
    } else {
        let inst_len = 2u32;
        if cursor + inst_len as usize > state.assembly_data.len() {
            state.counter += 1;
        } else {
            state.output_dict.insert(
                state.counter,
                AssemblyLine {
                    opcode: "repne cmpsd",
                    machine_code: byte_slice_to_hex_str(
                        &state.assembly_data[cursor..cursor + inst_len as usize],
                    ),
                    operand_1: Some(Cow::Borrowed("[edi]")),
                    operand_2: Some(Cow::Borrowed("[esi]")),
                },
            );
            state.counter += inst_len;
        }
    }
}

fn disassemble_instruction(state: &mut DisassemblerState) {
    let cursor: usize = state.counter as usize;
    match state.assembly_data.get(cursor).copied() {
        None => {
            state.counter += 1;
        }
        Some(opcode) => match opcode {
            ADD_EAX_IMM32 | AND_EAX_IMM32 | CMP_EAX_IMM32 | MOV_EAX_MOFFS32 | OR_EAX_IMM32
            | SUB_EAX_IMM32 | TEST_EAX_IMM32 | XOR_EAX_IMM32 => {
                disassemble_eax_imm32(state, opcode);
            }
            RM32_IMM32 => {
                disassemble_rm32_imm32(state);
            }
            ADD_RM32_R32 | AND_RM32_R32 | CMP_RM32_R32 | MOV_RM32_R32 | OR_RM32_R32
            | SUB_RM32_R32 | TEST_R32_RM32 | XOR_RM32_R32 => {
                disassemble_rm_reg(state, opcode);
            }
            ADD_R32_RM32 | AND_R32_RM32 | CMP_R32_RM32 | MOV_R32_RM32 | OR_R32_RM32
            | SUB_R32_RM32 | XOR_R32_RM32 => {
                disassemble_reg_rm(state, opcode);
            }
            CLFLUSH_0 => {
                disassemble_clflush(state);
            }
            DEC_INC_PUSH_RM32 => {
                disassemble_dec_inc_push_rm32(state);
            }
            DEC_BASE..=DEC_LIMIT => {
                disassemble_plus_reg(state, opcode, DEC_BASE, "dec");
            }
            INC_BASE..=INC_LIMIT => {
                disassemble_plus_reg(state, opcode, INC_BASE, "inc");
            }
            POP_BASE..=POP_LIMIT => {
                disassemble_plus_reg(state, opcode, POP_BASE, "pop");
            }
            PUSH_BASE..=PUSH_LIMIT => {
                disassemble_plus_reg(state, opcode, PUSH_BASE, "push");
            }
            IDIV_NOT_TEST_RM32 => {
                disassemble_idiv_not_test_rm32(state);
            }
            LEA_R32 => {
                disassemble_lea(state);
            }
            MOV_MOFFS32_EAX => {
                disassemble_mov_moffs32_eax(state);
            }
            MOV_R32_IMM32_BASE..=MOV_R32_IMM32_LIMIT => {
                disassemble_mov_r32_imm32(state, opcode);
            }
            0xc7 => {
                disassemble_mov_rm32_imm32(state);
            }
            MOVSD => {
                disassemble_movsd(state);
            }
            NOP => {
                disassemble_nop(state);
            }
            POP_RM32 => {
                disassemble_pop_rm32(state);
            }
            PUSH_IMM => {
                disassemble_push_imm(state);
            }
            REPNE_CMPSD_0 => {
                disassemble_repne_cmpsd(state);
            }
            _ => {
                state.counter += 1;
            }
        },
    }
}

#[repr(u8)]
#[derive(FromPrimitive, PartialEq)]
enum AddressingMode {
    Dereference = 0,
    ByteOffset,
    DwordOffset,
    DirectAccess,
}

#[repr(u8)]
#[derive(FromPrimitive, Debug, PartialEq, Copy, Clone)]
enum REG {
    Eax = 0,
    Ecx,
    Edx,
    Ebx,
    Esp,
    Ebp,
    Esi,
    Edi,
}

#[repr(u8)]
#[derive(FromPrimitive, Debug)]
enum RM {
    Eax = 0,
    Ecx,
    Edx,
    Ebx,
    EspSib,
    EbpDisp32,
    Esi,
    Edi,
}

struct ModRM {
    adressing_mode: AddressingMode,
    reg: REG,
    rm: RM,
}

impl ModRM {
    fn new(byte: u8) -> Self {
        Self {
            adressing_mode: FromPrimitive::from_u8(byte >> 6 & 0x3).unwrap(),
            reg: FromPrimitive::from_u8(byte >> 3 & 0x7).unwrap(),
            rm: FromPrimitive::from_u8(byte & 0x7).unwrap(),
        }
    }
}

impl fmt::Display for REG {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", format!("{:?}", self).to_lowercase())
    }
}

#[repr(u8)]
#[derive(FromPrimitive)]
enum Scale {
    Base = 0,
    Times2,
    Times4,
    Times8,
}

#[repr(u8)]
#[derive(FromPrimitive, Debug, PartialEq)]
enum Index {
    Eax = 0,
    Ecx,
    Edx,
    Ebx,
    None,
    Ebp,
    Esi,
    Edi,
}

#[repr(u8)]
#[derive(FromPrimitive, Debug, PartialEq)]
enum Base {
    Eax = 0,
    Ecx,
    Edx,
    Ebx,
    Esp,
    Star,
    Esi,
    Edi,
}

struct Sib {
    scale: Scale,
    index: Index,
    base: Base,
}

impl Sib {
    fn new(byte: u8) -> Self {
        Self {
            scale: FromPrimitive::from_u8(byte >> 6 & 0x3).unwrap(),
            index: FromPrimitive::from_u8(byte >> 3 & 0x7).unwrap(),
            base: FromPrimitive::from_u8(byte & 0x7).unwrap(),
        }
    }
}

enum Disp {
    Disp8(i8),
    Disp32(i32),
}

impl fmt::Display for Base {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", format!("{:?}", self).to_lowercase())
    }
}

impl fmt::Display for Index {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", format!("{:?}", self).to_lowercase())
    }
}

impl fmt::Display for RM {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::EbpDisp32 => write!(f, "ebp"),
            Self::EspSib => write!(f, "esp"),
            _ => write!(f, "{}", format!("{:?}", self).to_lowercase()),
        }
    }
}

fn build_sib_operand(sib: u8, md: &AddressingMode, offset: Option<Disp>) -> String {
    let sib = Sib::new(sib);
    let base_str = if sib.base == Base::Star {
        Cow::Borrowed(match md {
            AddressingMode::ByteOffset | AddressingMode::DwordOffset => "ebp",
            _ => "",
        })
    } else {
        Cow::Owned(format!("{}", sib.base))
    };
    let con_1 = if !base_str.is_empty() && sib.index != Index::None {
        " + "
    } else {
        ""
    };
    let index = if sib.index == Index::None {
        Cow::Borrowed("")
    } else {
        Cow::Owned(format!("{}", sib.index))
    };
    let scale = if sib.index == Index::None {
        ""
    } else {
        match sib.scale {
            Scale::Base => "",
            Scale::Times2 => "*2",
            Scale::Times4 => "*4",
            Scale::Times8 => "*8",
        }
    };
    let prefix = format!("{}{}{}{}", base_str, con_1, index, scale);
    let con_2 = if prefix.is_empty() || offset.is_none() {
        ""
    } else {
        match offset.as_ref().unwrap() {
            Disp::Disp8(off) => {
                if off.is_negative() {
                    " - "
                } else {
                    " + "
                }
            }
            Disp::Disp32(off) => {
                if off.is_negative() {
                    " - "
                } else {
                    " + "
                }
            }
        }
    };
    let offset_str = match offset {
        None => Cow::Borrowed(""),
        Some(off) => Cow::Owned(match off {
            Disp::Disp8(o) => format!("{:#04x}", o.unsigned_abs()),
            Disp::Disp32(o) => format!("{:#010x}", o.unsigned_abs()),
        }),
    };

    format!("[{}{}{}]", prefix, con_2, offset_str)
}

fn get_single_operand_from_digit_dereference(
    remaining_bytes: &[u8],
    bytes_for_inst: &mut u8,
    modrm: &ModRM,
) -> Option<String> {
    match modrm.rm {
        RM::EspSib => {
            if remaining_bytes.len() < 2 {
                None
            } else {
                let sib = Sib::new(remaining_bytes[1]);
                if sib.base == Base::Star {
                    if remaining_bytes.len() < 6 {
                        None
                    } else {
                        *bytes_for_inst = 6;
                        let disp = i32::from_le_bytes(remaining_bytes[2..6].try_into().unwrap());
                        Some(build_sib_operand(
                            remaining_bytes[1],
                            &AddressingMode::Dereference,
                            if disp == 0 {
                                None
                            } else {
                                Some(Disp::Disp32(disp))
                            },
                        ))
                    }
                } else {
                    *bytes_for_inst = 2;
                    Some(build_sib_operand(
                        remaining_bytes[1],
                        &AddressingMode::Dereference,
                        None,
                    ))
                }
            }
        }
        RM::EbpDisp32 => {
            if remaining_bytes.len() < 5 {
                None
            } else {
                *bytes_for_inst = 5;
                let ptr = u32::from_le_bytes(remaining_bytes[1..5].try_into().unwrap());
                Some(format!("[{:#010x}]", ptr))
            }
        }
        _ => {
            *bytes_for_inst = 1;
            Some(format!("[{}]", modrm.rm))
        }
    }
}

fn get_single_operand_from_digit_byteoffset(
    remaining_bytes: &[u8],
    bytes_for_inst: &mut u8,
    modrm: &ModRM,
) -> Option<String> {
    match modrm.rm {
        RM::EspSib => {
            if remaining_bytes.len() < 3 {
                None
            } else {
                *bytes_for_inst = 3;
                #[allow(clippy::cast_possible_wrap)]
                Some(build_sib_operand(
                    remaining_bytes[1],
                    &AddressingMode::ByteOffset,
                    if remaining_bytes[2] == 0 {
                        None
                    } else {
                        Some(Disp::Disp8(remaining_bytes[2] as i8))
                    },
                ))
            }
        }
        _ => {
            if remaining_bytes.len() < 2 {
                None
            } else {
                *bytes_for_inst = 2;
                #[allow(clippy::cast_possible_wrap)]
                if remaining_bytes[1] == 0 {
                    Some(format!("[{}]", modrm.rm))
                } else if (remaining_bytes[1] as i8).is_negative() {
                    Some(format!(
                        "[{} - {:#04x}]",
                        modrm.rm,
                        (remaining_bytes[1] as i8).unsigned_abs()
                    ))
                } else {
                    Some(format!(
                        "[{} + {:#04x}]",
                        modrm.rm,
                        (remaining_bytes[1] as i8).unsigned_abs()
                    ))
                }
            }
        }
    }
}

fn get_single_operand_from_digit_dwordoffset(
    remaining_bytes: &[u8],
    bytes_for_inst: &mut u8,
    modrm: &ModRM,
) -> Option<String> {
    match modrm.rm {
        RM::EspSib => {
            if remaining_bytes.len() < 6 {
                None
            } else {
                *bytes_for_inst = 6;
                let offset = i32::from_le_bytes(remaining_bytes[2..6].try_into().unwrap());
                Some(build_sib_operand(
                    remaining_bytes[1],
                    &AddressingMode::DwordOffset,
                    if offset == 0 {
                        None
                    } else {
                        Some(Disp::Disp32(offset))
                    },
                ))
            }
        }
        _ => {
            if remaining_bytes.len() < 5 {
                None
            } else {
                *bytes_for_inst = 5;
                let offset = i32::from_le_bytes(remaining_bytes[1..5].try_into().unwrap());
                if offset == 0 {
                    Some(format!("[{}]", modrm.rm))
                } else if offset.is_negative() {
                    Some(format!("[{} - {:#010x}]", modrm.rm, offset.unsigned_abs()))
                } else {
                    Some(format!("[{} + {:#010x}]", modrm.rm, offset.unsigned_abs()))
                }
            }
        }
    }
}

fn get_single_operand_from_digit(
    remaining_bytes: &[u8],
    digit: u8,
    bytes_for_inst: &mut u8,
) -> Option<String> {
    let modrm = ModRM::new(remaining_bytes[0]);
    if modrm.reg != FromPrimitive::from_u8(digit).unwrap() {
        return None;
    }
    match modrm.adressing_mode {
        AddressingMode::Dereference => {
            get_single_operand_from_digit_dereference(remaining_bytes, bytes_for_inst, &modrm)
        }
        AddressingMode::ByteOffset => {
            get_single_operand_from_digit_byteoffset(remaining_bytes, bytes_for_inst, &modrm)
        }
        AddressingMode::DwordOffset => {
            get_single_operand_from_digit_dwordoffset(remaining_bytes, bytes_for_inst, &modrm)
        }
        AddressingMode::DirectAccess => {
            *bytes_for_inst = 1;
            Some(format!("{}", modrm.rm))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::get_single_operand_from_digit;
    #[test]
    fn test_get_single_operand_from_digit_0() {
        let remaing_bytes = vec![0x14, 0x4d, 0x44, 0x33, 0x22, 0x11];
        let mut bytes_for_inst = 0;
        let operand = get_single_operand_from_digit(&remaing_bytes, 2, &mut bytes_for_inst);
        assert!(operand.is_some());
        assert_eq!(operand.unwrap(), "[ecx*2 + 0x11223344]");
        assert_eq!(bytes_for_inst, 6);
    }
    #[test]
    fn test_get_single_operand_from_digit_1() {
        let remaing_bytes = vec![0x54, 0xb1, 0x25];
        let mut bytes_for_inst = 0;
        let operand = get_single_operand_from_digit(&remaing_bytes, 2, &mut bytes_for_inst);
        assert!(operand.is_some());
        assert_eq!(operand.unwrap(), "[ecx + esi*4 + 0x25]");
        assert_eq!(bytes_for_inst, 3);
    }
    #[test]
    fn test_get_single_operand_from_digit_2() {
        let remaing_bytes = vec![0x54, 0xa1, 0x25];
        let mut bytes_for_inst = 0;
        let operand = get_single_operand_from_digit(&remaing_bytes, 2, &mut bytes_for_inst);
        assert!(operand.is_some());
        assert_eq!(operand.unwrap(), "[ecx + 0x25]");
        assert_eq!(bytes_for_inst, 3);
    }
    #[test]
    fn test_get_single_operand_from_digit_3() {
        let remaing_bytes = vec![0x51, 0x5];
        let mut bytes_for_inst = 0;
        let operand = get_single_operand_from_digit(&remaing_bytes, 2, &mut bytes_for_inst);
        assert!(operand.is_some());
        assert_eq!(operand.unwrap(), "[ecx + 0x05]");
        assert_eq!(bytes_for_inst, 2);
    }
}
