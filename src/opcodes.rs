//! The Tapleaf 0xC2 opcode set: what each byte means as an instruction.
//!
//! Names, classes and stack effects follow jmoik/bitcoin `gsr` @ `ad6c16f` (`src/script/script.h`, `script.cpp`
//! and `interpreter.cpp`). `tests/core.rs` checks them against a fixture extracted from that source by
//! `contrib/extract-core.py`. Bytes without a name in Bitcoin Core are named `OP_PUSHBYTES_n` (pushes of 1–75
//! bytes) and `OP_SUCCESSn` (BIP 342 style).

use std::fmt;

/// An instruction byte.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Opcode(u8);

/// What an opcode does as an instruction of a Tapleaf 0xC2 script.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    /// Pushes the next n bytes: `OP_0` (n = 0) and `OP_PUSHBYTES_1` to `OP_PUSHBYTES_75`.
    PushBytes(u8),
    /// `OP_PUSHDATA1`, `OP_PUSHDATA2`, `OP_PUSHDATA4`: a little-endian length of this many bytes, then the data.
    PushData(u8),
    /// `OP_1` to `OP_16`: pushes this number.
    PushNum(u8),
    /// The leaf succeeds unconditionally if this byte is decoded as an instruction, anywhere in the script, even in a
    /// macro body that is never referenced (BIP 441). Includes `OP_1NEGATE`, `OP_NEGATE` and `OP_ABS`, which are
    /// ordinary opcodes in Tapscript.
    OpSuccess,
    /// Fails when reached, even in a branch that is not executed: `OP_VERIF`, `OP_VERNOTIF`.
    FailsWhenReached,
    /// Fails when executed: `OP_RETURN`, `OP_CHECKMULTISIG`, `OP_CHECKMULTISIGVERIFY`, `OP_INVALIDOPCODE`.
    FailsWhenExecuted,
    /// Does nothing, but policy rejects it when executed, keeping it for upgrades: `OP_NOP1`, `OP_NOP4`–`OP_NOP10`.
    UpgradableNop,
    /// `OP_IF`, `OP_NOTIF`, `OP_ELSE`, `OP_ENDIF`.
    Conditional,
    /// `OP_MACRO`, `OP_CALLMACRO`: decoded and unrolled before execution, never executed.
    Macro,
    /// Any other opcode.
    Operation,
}

/// Where an opcode comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Origin {
    /// Bitcoin's original opcode set.
    Base,
    /// BIP 342 (Tapscript): `OP_CHECKSIGADD`.
    Tapscript,
    /// Re-enabled for Tapleaf 0xC2 by BIP 441: `OP_CAT`, `OP_MUL`, `OP_LSHIFT`, …
    Bip441,
    /// The Extended Primitives draft: `OP_TWEAKADD`, `OP_CHECKSIGFROMSTACK`, `OP_BYTEREV`.
    ExtendedPrimitives,
    /// The OP_TX draft: `OP_TX`.
    OpTx,
    /// The reusable macros draft: `OP_MACRO`, `OP_CALLMACRO`.
    ReusableMacros,
}

/// What an executed instruction takes from and leaves on the stacks, as in Forth's `( x1 x2 -- out )`: it needs
/// `pop` items on the stack, removes them and pushes `push` items; likewise for the altstack.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StackEffect {
    pub pop: u8,
    pub push: u8,
    pub alt_pop: u8,
    pub alt_push: u8,
}

const fn effect(pop: u8, push: u8) -> Option<StackEffect> {
    Some(StackEffect { pop, push, alt_pop: 0, alt_push: 0 })
}

impl Opcode {
    pub const fn from_u8(byte: u8) -> Self {
        Opcode(byte)
    }

    pub const fn to_u8(self) -> u8 {
        self.0
    }

    pub fn name(self) -> &'static str {
        NAMES[self.0 as usize]
    }

    /// The opcode with this name, aliases (`OP_FALSE`, `OP_TRUE`, `OP_NOP2`, `OP_NOP3`) included.
    pub fn from_name(name: &str) -> Option<Self> {
        let primary = NAMES.iter().position(|&n| n == name).map(|b| Opcode(b as u8));
        primary.or_else(|| NAMED.iter().find(|&&(n, _)| n == name).map(|&(_, op)| op))
    }

    pub const fn class(self) -> Class {
        match self.0 {
            0x00..=0x4b => Class::PushBytes(self.0),
            0x4c => Class::PushData(1),
            0x4d => Class::PushData(2),
            0x4e => Class::PushData(4),
            0x51..=0x60 => Class::PushNum(self.0 - 0x50),
            // OP_1NEGATE, OP_NEGATE, OP_ABS (BIP 441), OP_RESERVED, OP_VER, OP_RESERVED1, OP_RESERVED2 and the
            // unassigned bytes
            0x4f | 0x8f | 0x90 | 0x50 | 0x62 | 0x89 | 0x8a => Class::OpSuccess,
            0xbb..=0xbd | 0xc0..=0xcb | 0xcd | 0xce | 0xd2..=0xfe => Class::OpSuccess,
            0x65 | 0x66 => Class::FailsWhenReached,
            0x6a | 0xae | 0xaf | 0xff => Class::FailsWhenExecuted,
            0xb0 | 0xb3..=0xb9 => Class::UpgradableNop,
            0x63 | 0x64 | 0x67 | 0x68 => Class::Conditional,
            0xd0 | 0xd1 => Class::Macro,
            _ => Class::Operation,
        }
    }

    pub const fn is_op_success(self) -> bool {
        matches!(self.class(), Class::OpSuccess)
    }

    /// The stack effect when executed, or `None` when it depends on the operands (`OP_PICK`, `OP_ROLL`, `OP_IFDUP`,
    /// `OP_TX`) or the instruction never completes (OP_SUCCESSx, failing and macro opcodes).
    pub const fn stack_effect(self) -> Option<StackEffect> {
        match self.class() {
            Class::PushBytes(_) | Class::PushData(_) | Class::PushNum(_) => effect(0, 1),
            Class::OpSuccess | Class::FailsWhenReached | Class::FailsWhenExecuted | Class::Macro => None,
            Class::UpgradableNop => effect(0, 0),
            Class::Conditional => match self.0 {
                0x63 | 0x64 => effect(1, 0), // OP_IF, OP_NOTIF
                _ => effect(0, 0),
            },
            Class::Operation => match self.0 {
                0x61 | 0xab => effect(0, 0), // OP_NOP, OP_CODESEPARATOR
                0x69 => effect(1, 0),        // OP_VERIFY
                0x6b => Some(StackEffect { pop: 1, push: 0, alt_pop: 0, alt_push: 1 }), // OP_TOALTSTACK
                0x6c => Some(StackEffect { pop: 0, push: 1, alt_pop: 1, alt_push: 0 }), // OP_FROMALTSTACK
                0x6d => effect(2, 0),        // OP_2DROP
                0x6e => effect(2, 4),        // OP_2DUP
                0x6f => effect(3, 6),        // OP_3DUP
                0x70 => effect(4, 6),        // OP_2OVER
                0x71 => effect(6, 6),        // OP_2ROT
                0x72 => effect(4, 4),        // OP_2SWAP
                0x73 | 0x79 | 0x7a | 0xbf => None, // OP_IFDUP, OP_PICK, OP_ROLL, OP_TX
                0x74 => effect(0, 1),        // OP_DEPTH
                0x75 => effect(1, 0),        // OP_DROP
                0x76 => effect(1, 2),        // OP_DUP
                0x77 => effect(2, 1),        // OP_NIP
                0x78 => effect(2, 3),        // OP_OVER
                0x7b => effect(3, 3),        // OP_ROT
                0x7c => effect(2, 2),        // OP_SWAP
                0x7d => effect(2, 3),        // OP_TUCK
                0x7f | 0xa5 | 0xba | 0xcc => effect(3, 1), // OP_SUBSTR, OP_WITHIN, OP_CHECKSIGADD, OP_CHECKSIGFROMSTACK
                0x82 => effect(1, 2),        // OP_SIZE
                0x88 | 0x9d | 0xad => effect(2, 0), // OP_EQUALVERIFY, OP_NUMEQUALVERIFY, OP_CHECKSIGVERIFY
                // OP_INVERT, OP_1ADD, OP_1SUB, OP_2MUL, OP_2DIV, OP_NOT, OP_0NOTEQUAL, the hashes,
                // OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_BYTEREV
                0x83 | 0x8b..=0x8e | 0x91 | 0x92 | 0xa6..=0xaa | 0xb1 | 0xb2 | 0xcf => effect(1, 1),
                // the remaining binary operations: OP_CAT, OP_LEFT, OP_AND, OP_EQUAL, OP_ADD, OP_MUL, OP_LSHIFT,
                // OP_BOOLAND, OP_NUMEQUAL, OP_LESSTHAN, OP_MIN, OP_CHECKSIG, OP_TWEAKADD, …
                _ => effect(2, 1),
            },
        }
    }

    /// Where the opcode comes from; `None` for the unassigned OP_SUCCESSx bytes.
    pub const fn origin(self) -> Option<Origin> {
        match self.0 {
            0x7e..=0x81 | 0x83..=0x86 | 0x8d | 0x8e | 0x95..=0x99 => Some(Origin::Bip441),
            0xba => Some(Origin::Tapscript),
            0xbe | 0xcc | 0xcf => Some(Origin::ExtendedPrimitives),
            0xbf => Some(Origin::OpTx),
            0xd0 | 0xd1 => Some(Origin::ReusableMacros),
            0xbb..=0xbd | 0xc0..=0xcb | 0xcd | 0xce | 0xd2..=0xfe => None,
            _ => Some(Origin::Base),
        }
    }
}

impl From<u8> for Opcode {
    fn from(byte: u8) -> Self {
        Opcode(byte)
    }
}

impl From<Opcode> for u8 {
    fn from(op: Opcode) -> Self {
        op.0
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl fmt::Debug for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

macro_rules! named {
    ($($name:ident = $byte:literal,)*) => {
        $(pub const $name: Opcode = Opcode($byte);)*
        /// Every named opcode constant, aliases included.
        pub const NAMED: &[(&str, Opcode)] = &[$((stringify!($name), $name)),*];
    };
}

named! {
    OP_0 = 0x00,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    OP_SIZE = 0x82,
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,
    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,
    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,
    OP_WITHIN = 0xa5,
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,
    OP_NOP1 = 0xb0,
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,
    OP_CHECKSIGADD = 0xba,
    OP_TWEAKADD = 0xbe,
    OP_TX = 0xbf,
    OP_CHECKSIGFROMSTACK = 0xcc,
    OP_BYTEREV = 0xcf,
    OP_MACRO = 0xd0,
    OP_CALLMACRO = 0xd1,
    OP_INVALIDOPCODE = 0xff,
    OP_FALSE = 0x00,
    OP_TRUE = 0x51,
    OP_NOP2 = 0xb1,
    OP_NOP3 = 0xb2,
}

/// Each byte's name.
static NAMES: [&str; 256] = [
    "OP_0",
    "OP_PUSHBYTES_1",
    "OP_PUSHBYTES_2",
    "OP_PUSHBYTES_3",
    "OP_PUSHBYTES_4",
    "OP_PUSHBYTES_5",
    "OP_PUSHBYTES_6",
    "OP_PUSHBYTES_7",
    "OP_PUSHBYTES_8",
    "OP_PUSHBYTES_9",
    "OP_PUSHBYTES_10",
    "OP_PUSHBYTES_11",
    "OP_PUSHBYTES_12",
    "OP_PUSHBYTES_13",
    "OP_PUSHBYTES_14",
    "OP_PUSHBYTES_15",
    "OP_PUSHBYTES_16",
    "OP_PUSHBYTES_17",
    "OP_PUSHBYTES_18",
    "OP_PUSHBYTES_19",
    "OP_PUSHBYTES_20",
    "OP_PUSHBYTES_21",
    "OP_PUSHBYTES_22",
    "OP_PUSHBYTES_23",
    "OP_PUSHBYTES_24",
    "OP_PUSHBYTES_25",
    "OP_PUSHBYTES_26",
    "OP_PUSHBYTES_27",
    "OP_PUSHBYTES_28",
    "OP_PUSHBYTES_29",
    "OP_PUSHBYTES_30",
    "OP_PUSHBYTES_31",
    "OP_PUSHBYTES_32",
    "OP_PUSHBYTES_33",
    "OP_PUSHBYTES_34",
    "OP_PUSHBYTES_35",
    "OP_PUSHBYTES_36",
    "OP_PUSHBYTES_37",
    "OP_PUSHBYTES_38",
    "OP_PUSHBYTES_39",
    "OP_PUSHBYTES_40",
    "OP_PUSHBYTES_41",
    "OP_PUSHBYTES_42",
    "OP_PUSHBYTES_43",
    "OP_PUSHBYTES_44",
    "OP_PUSHBYTES_45",
    "OP_PUSHBYTES_46",
    "OP_PUSHBYTES_47",
    "OP_PUSHBYTES_48",
    "OP_PUSHBYTES_49",
    "OP_PUSHBYTES_50",
    "OP_PUSHBYTES_51",
    "OP_PUSHBYTES_52",
    "OP_PUSHBYTES_53",
    "OP_PUSHBYTES_54",
    "OP_PUSHBYTES_55",
    "OP_PUSHBYTES_56",
    "OP_PUSHBYTES_57",
    "OP_PUSHBYTES_58",
    "OP_PUSHBYTES_59",
    "OP_PUSHBYTES_60",
    "OP_PUSHBYTES_61",
    "OP_PUSHBYTES_62",
    "OP_PUSHBYTES_63",
    "OP_PUSHBYTES_64",
    "OP_PUSHBYTES_65",
    "OP_PUSHBYTES_66",
    "OP_PUSHBYTES_67",
    "OP_PUSHBYTES_68",
    "OP_PUSHBYTES_69",
    "OP_PUSHBYTES_70",
    "OP_PUSHBYTES_71",
    "OP_PUSHBYTES_72",
    "OP_PUSHBYTES_73",
    "OP_PUSHBYTES_74",
    "OP_PUSHBYTES_75",
    "OP_PUSHDATA1",
    "OP_PUSHDATA2",
    "OP_PUSHDATA4",
    "OP_1NEGATE",
    "OP_RESERVED",
    "OP_1",
    "OP_2",
    "OP_3",
    "OP_4",
    "OP_5",
    "OP_6",
    "OP_7",
    "OP_8",
    "OP_9",
    "OP_10",
    "OP_11",
    "OP_12",
    "OP_13",
    "OP_14",
    "OP_15",
    "OP_16",
    "OP_NOP",
    "OP_VER",
    "OP_IF",
    "OP_NOTIF",
    "OP_VERIF",
    "OP_VERNOTIF",
    "OP_ELSE",
    "OP_ENDIF",
    "OP_VERIFY",
    "OP_RETURN",
    "OP_TOALTSTACK",
    "OP_FROMALTSTACK",
    "OP_2DROP",
    "OP_2DUP",
    "OP_3DUP",
    "OP_2OVER",
    "OP_2ROT",
    "OP_2SWAP",
    "OP_IFDUP",
    "OP_DEPTH",
    "OP_DROP",
    "OP_DUP",
    "OP_NIP",
    "OP_OVER",
    "OP_PICK",
    "OP_ROLL",
    "OP_ROT",
    "OP_SWAP",
    "OP_TUCK",
    "OP_CAT",
    "OP_SUBSTR",
    "OP_LEFT",
    "OP_RIGHT",
    "OP_SIZE",
    "OP_INVERT",
    "OP_AND",
    "OP_OR",
    "OP_XOR",
    "OP_EQUAL",
    "OP_EQUALVERIFY",
    "OP_RESERVED1",
    "OP_RESERVED2",
    "OP_1ADD",
    "OP_1SUB",
    "OP_2MUL",
    "OP_2DIV",
    "OP_NEGATE",
    "OP_ABS",
    "OP_NOT",
    "OP_0NOTEQUAL",
    "OP_ADD",
    "OP_SUB",
    "OP_MUL",
    "OP_DIV",
    "OP_MOD",
    "OP_LSHIFT",
    "OP_RSHIFT",
    "OP_BOOLAND",
    "OP_BOOLOR",
    "OP_NUMEQUAL",
    "OP_NUMEQUALVERIFY",
    "OP_NUMNOTEQUAL",
    "OP_LESSTHAN",
    "OP_GREATERTHAN",
    "OP_LESSTHANOREQUAL",
    "OP_GREATERTHANOREQUAL",
    "OP_MIN",
    "OP_MAX",
    "OP_WITHIN",
    "OP_RIPEMD160",
    "OP_SHA1",
    "OP_SHA256",
    "OP_HASH160",
    "OP_HASH256",
    "OP_CODESEPARATOR",
    "OP_CHECKSIG",
    "OP_CHECKSIGVERIFY",
    "OP_CHECKMULTISIG",
    "OP_CHECKMULTISIGVERIFY",
    "OP_NOP1",
    "OP_CHECKLOCKTIMEVERIFY",
    "OP_CHECKSEQUENCEVERIFY",
    "OP_NOP4",
    "OP_NOP5",
    "OP_NOP6",
    "OP_NOP7",
    "OP_NOP8",
    "OP_NOP9",
    "OP_NOP10",
    "OP_CHECKSIGADD",
    "OP_SUCCESS187",
    "OP_SUCCESS188",
    "OP_SUCCESS189",
    "OP_TWEAKADD",
    "OP_TX",
    "OP_SUCCESS192",
    "OP_SUCCESS193",
    "OP_SUCCESS194",
    "OP_SUCCESS195",
    "OP_SUCCESS196",
    "OP_SUCCESS197",
    "OP_SUCCESS198",
    "OP_SUCCESS199",
    "OP_SUCCESS200",
    "OP_SUCCESS201",
    "OP_SUCCESS202",
    "OP_SUCCESS203",
    "OP_CHECKSIGFROMSTACK",
    "OP_SUCCESS205",
    "OP_SUCCESS206",
    "OP_BYTEREV",
    "OP_MACRO",
    "OP_CALLMACRO",
    "OP_SUCCESS210",
    "OP_SUCCESS211",
    "OP_SUCCESS212",
    "OP_SUCCESS213",
    "OP_SUCCESS214",
    "OP_SUCCESS215",
    "OP_SUCCESS216",
    "OP_SUCCESS217",
    "OP_SUCCESS218",
    "OP_SUCCESS219",
    "OP_SUCCESS220",
    "OP_SUCCESS221",
    "OP_SUCCESS222",
    "OP_SUCCESS223",
    "OP_SUCCESS224",
    "OP_SUCCESS225",
    "OP_SUCCESS226",
    "OP_SUCCESS227",
    "OP_SUCCESS228",
    "OP_SUCCESS229",
    "OP_SUCCESS230",
    "OP_SUCCESS231",
    "OP_SUCCESS232",
    "OP_SUCCESS233",
    "OP_SUCCESS234",
    "OP_SUCCESS235",
    "OP_SUCCESS236",
    "OP_SUCCESS237",
    "OP_SUCCESS238",
    "OP_SUCCESS239",
    "OP_SUCCESS240",
    "OP_SUCCESS241",
    "OP_SUCCESS242",
    "OP_SUCCESS243",
    "OP_SUCCESS244",
    "OP_SUCCESS245",
    "OP_SUCCESS246",
    "OP_SUCCESS247",
    "OP_SUCCESS248",
    "OP_SUCCESS249",
    "OP_SUCCESS250",
    "OP_SUCCESS251",
    "OP_SUCCESS252",
    "OP_SUCCESS253",
    "OP_SUCCESS254",
    "OP_INVALIDOPCODE",
];
