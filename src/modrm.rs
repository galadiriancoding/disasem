use std::fmt;

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use crate::sib::{build_sib_operand, Base, Disp, Sib};

#[repr(u8)]
#[derive(FromPrimitive, PartialEq, Eq)]
pub enum AddressingMode {
    Dereference = 0,
    ByteOffset,
    DwordOffset,
    DirectAccess,
}

#[repr(u8)]
#[derive(FromPrimitive, Debug, PartialEq, Eq, Copy, Clone)]
pub enum REG {
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
pub enum RM {
    Eax = 0,
    Ecx,
    Edx,
    Ebx,
    EspSib,
    EbpDisp32,
    Esi,
    Edi,
}

pub struct ModRM {
    pub adressing_mode: AddressingMode,
    pub reg: REG,
    rm: RM,
}

impl ModRM {
    pub fn new(byte: u8) -> Self {
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

impl fmt::Display for RM {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::EbpDisp32 => write!(f, "ebp"),
            Self::EspSib => write!(f, "esp"),
            _ => write!(f, "{}", format!("{:?}", self).to_lowercase()),
        }
    }
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

pub fn get_single_operand_from_digit(
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
    use crate::modrm::get_single_operand_from_digit;

    #[test]
    fn test_get_single_operand_from_digit_0() {
        let remaing_bytes = vec![0x14, 0x4D, 0x44, 0x33, 0x22, 0x11];
        let mut bytes_for_inst = 0;
        let operand = get_single_operand_from_digit(&remaing_bytes, 2, &mut bytes_for_inst);
        assert!(operand.is_some());
        assert_eq!(operand.unwrap(), "[ecx*2 + 0x11223344]");
        assert_eq!(bytes_for_inst, 6);
    }
    #[test]
    fn test_get_single_operand_from_digit_1() {
        let remaing_bytes = vec![0x54, 0xB1, 0x25];
        let mut bytes_for_inst = 0;
        let operand = get_single_operand_from_digit(&remaing_bytes, 2, &mut bytes_for_inst);
        assert!(operand.is_some());
        assert_eq!(operand.unwrap(), "[ecx + esi*4 + 0x25]");
        assert_eq!(bytes_for_inst, 3);
    }
    #[test]
    fn test_get_single_operand_from_digit_2() {
        let remaing_bytes = vec![0x54, 0xA1, 0x25];
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
