use std::{borrow::Cow, fmt};

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use crate::modrm::AddressingMode;

#[repr(u8)]
#[derive(FromPrimitive)]
pub enum Scale {
    Base = 0,
    Times2,
    Times4,
    Times8,
}

#[repr(u8)]
#[derive(FromPrimitive, Debug, PartialEq, Eq)]
pub enum Index {
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
#[derive(FromPrimitive, Debug, PartialEq, Eq)]
pub enum Base {
    Eax = 0,
    Ecx,
    Edx,
    Ebx,
    Esp,
    Star,
    Esi,
    Edi,
}
pub enum Disp {
    Disp8(i8),
    Disp32(i32),
}
pub struct Sib {
    scale: Scale,
    index: Index,
    pub base: Base,
}

impl Sib {
    pub fn new(byte: u8) -> Self {
        Self {
            scale: FromPrimitive::from_u8(byte >> 6 & 0x3).unwrap(),
            index: FromPrimitive::from_u8(byte >> 3 & 0x7).unwrap(),
            base: FromPrimitive::from_u8(byte & 0x7).unwrap(),
        }
    }
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

pub fn build_sib_operand(sib: u8, md: &AddressingMode, offset: Option<Disp>) -> String {
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
