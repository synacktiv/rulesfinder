use std::collections::HashMap;

#[derive(Hash, Eq, PartialEq, Debug, Clone, PartialOrd)]
enum ToolSupport {
    JtR,
    Hashcat,
    Both,
}

static CONV_SOURCE: &str = "`1234567890-=\\qwertyuiop[]asdfghjkl;'zxcvbnm,./~!@#$%^&*()_+|QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?";
static CONV_SHIFT: &str = "~!@#$%^&*()_+|QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?`1234567890-=\\qwertyuiop[]asdfghjkl;'zxcvbnm,./";
static CONV_INVERT: &str = "`1234567890-=\\QWERTYUIOP[]ASDFGHJKL;'ZXCVBNM,./~!@#$%^&*()_+|qwertyuiop{}asdfghjkl:\"zxcvbnm<>?";
static CONV_VOWELS: &str = "`1234567890-=\\QWeRTYuioP[]aSDFGHJKL;'ZXCVBNM,./~!@#$%^&*()_+|QWeRTYuioP{}aSDFGHJKL:\"ZXCVBNM<>?";
static CONV_RIGHT: &str = "1234567890-=\\\\wertyuiop[]]sdfghjkl;''xcvbnm,./\\!@#$%^&*()_+||WERTYUIOP{}}SDFGHJKL:\"\"XCVBNM<>?|";
static CONV_LEFT: &str = "``1234567890-=qqwertyuiop[aasdfghjkl;zzxcvbnm,.~~!@#$%^&*()_+QQWERTYUIOP{AASDFGHJKL:ZZXCVBNM<>";

static CHARS_VOWELS: &[u8] = b"aeiouAEIOU";
static CHARS_CONSONANTS: &[u8] = b"bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ";
static CHARS_WHITESPACE: &[u8] = b" \t";
static CHARS_PUNCTUATION: &[u8] = b".,:;'\x22?!`";
static CHARS_SPECIALS: &[u8] = b"$%^&*()-_+=|\\<>[]{}#@/~";
static CHARS_CONTROL_ASCII: &[u8] = &[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x7F, 0x84,
    0x85, 0x88, 0x8D, 0x8E, 0x8F, 0x90, 0x96, 0x97, 0x98, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
];

static STR_SEPARATORS: &[u8] = b"\"'/,;:!?.azertyuiopqsdfghjklmwxcvbn";

fn rules_init_conv(ssrc: &str, sdst: &str) -> [u8; 256] {
    let mut out = [0; 256];
    let src = ssrc.as_bytes();
    let dst = sdst.as_bytes();
    if src.len() != dst.len() {
        panic!("src & dst must be of the same size!");
    }
    for (&s, &d) in src.iter().zip(dst.iter()) {
        out[s as usize] = d;
    }
    out
}

pub struct Converts {
    cshift: [u8; 256],
    cinvert: [u8; 256],
    cleft: [u8; 256],
    cright: [u8; 256],
    cvowels: [u8; 256],
}

pub fn make_converts() -> Converts {
    Converts {
        cshift: rules_init_conv(CONV_SOURCE, CONV_SHIFT),
        cinvert: rules_init_conv(CONV_SOURCE, CONV_INVERT),
        cleft: rules_init_conv(CONV_SOURCE, CONV_LEFT),
        cright: rules_init_conv(CONV_SOURCE, CONV_RIGHT),
        cvowels: rules_init_conv(CONV_SOURCE, CONV_VOWELS),
    }
}

#[allow(dead_code)]
#[derive(Hash, Eq, PartialEq, Debug, Clone, PartialOrd)]
pub enum UserVar {
    UVA,
    UVB,
    UVC,
    UVD,
    UVE,
    UVF,
    UVG,
    UVH,
    UVI,
    UVJ,
    UVK,
}

#[allow(dead_code)]
fn rand_uservar<T: rand::Rng>(rng: &mut T) -> UserVar {
    use UserVar::*;
    match rng.gen_range(0, 11) {
        0 => UVA,
        1 => UVB,
        2 => UVC,
        3 => UVD,
        4 => UVE,
        5 => UVF,
        6 => UVG,
        7 => UVH,
        8 => UVI,
        9 => UVJ,
        _ => UVK,
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd)]
pub enum Numerical {
    Val(u8),
    MinLen,
    MinLenMinus1,
    MinLenPlus1,
    MaxLen,
    MaxLenMinus1,
    MaxLenPlus1,
    SavedLen(UserVar),
    WordLen,
    WordLastCharPos,
    LastFound,
    Infinite,
}

#[allow(dead_code)]
fn rand_numerical<T: rand::Rng>(rng: &mut T) -> Numerical {
    use Numerical::*;
    match rng.gen_range(0, 30) {
        0 => MinLen,
        1 => MinLenMinus1,
        2 => MinLenPlus1,
        3 => MaxLen,
        4 => MaxLenMinus1,
        5 => MaxLenPlus1,
        6 => SavedLen(rand_uservar(rng)),
        7 => WordLen,
        8 => WordLastCharPos,
        9 => LastFound,
        10 => Infinite,
        _ => Val(rng.gen_range(0, 10)),
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd)]
pub enum RejectRule {
    Noop,
    UnlessCaseSensitive,
    Unless8bits,
    UnlessSplit,
    UnlessWordPairs,
    UnlessUtf8,
    IfUtf8,
    UnlessSupportedLengthOrLonger(Numerical),
    UnlessSupportedLengthOrShorted(Numerical),
    UnlessWordLengthLessThan(Numerical),
    UnlessWordLengthMoreThan(Numerical),
    UnlessWordLengthIs(Numerical),
    UnlessValidAfterAdding(Numerical),
    UnlessValidAfterRemoving(Numerical),
    IfContain(CharSelector),
    UnlessContain(CharSelector),
    UnlessCharAt(Numerical, CharSelector),
    UnlessFirstChar(CharSelector),
    UnlessLastChar(CharSelector),
    UnlessAtLeastNTimes(Numerical, CharSelector),
    UnlessValidUtf8,
    RejectTheWordUnlessDifferent,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd)]
pub enum CharSelector {
    OneOf(CharClass),
    NoneOf(CharClass),
}

fn rand_charselector<T: rand::Rng>(rng: &mut T) -> CharSelector {
    let c = rand_charclass(rng);
    if rng.gen() {
        CharSelector::OneOf(c)
    } else {
        CharSelector::NoneOf(c)
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd)]
pub enum CharClass {
    CCVowels,
    CCConsonants,
    CCWhitespace,
    CCPunctuation,
    CCSymbols,
    CCLower,
    CCUpper,
    CCDigits,
    CCLetters,
    CCAlphaNum,
    CCControl,
    // CCValid,
    CCAll,
    CCBit8,
    CCSingle(u8), // TODO: user defined
}

#[allow(dead_code)]
fn rand_charclass<T: rand::Rng>(rng: &mut T) -> CharClass {
    use CharClass::*;
    match rng.gen_range(0, 20) {
        0 => CCVowels,
        1 => CCConsonants,
        2 => CCWhitespace,
        3 => CCPunctuation,
        4 => CCSymbols,
        5 => CCLower,
        6 => CCUpper,
        7 => CCDigits,
        8 => CCLetters,
        9 => CCAlphaNum,
        10 => CCControl,
        11 => CCAll,
        12 => CCBit8,
        _ => CCSingle(rng.gen()),
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd)]
pub enum CommandRule {
    Noop,
    ToLower,
    ToUpper,
    Capitalize,
    InvertCapitalize,
    ToggleAll,
    ShiftAll,
    LowerVowelsUpperConsonants,
    ShiftAllKeyboardRight,
    ShiftAllKeyboardLeft,
    Reverse,
    Duplicate,
    Reflect,
    RotLeft,
    RotRight,
    SwapFirstTwo,
    SwapLastTwo,
    AppendMemory,
    PrependMemory,
    DupeAllChar,
    Pluralize,
    PastTense,
    Genitive,
    DeleteFirst,
    DeleteLast,
    Memorize,
    ToggleCase(Numerical),
    ToggleShift(Numerical),
    DeleteAt(Numerical),
    PurgeAll(CharSelector),
    TitleCase(CharSelector),
    DupWordNTimes(Numerical),
    BitshiftRight(Numerical),
    BitshiftLeft(Numerical),
    Swap(Numerical, Numerical),
    Increment(Numerical),
    Decrement(Numerical),
    DupeFirstChar(Numerical),
    DupeLastChar(Numerical),
    ReplaceWithNext(Numerical),
    ReplaceWithPrior(Numerical),
    DupFirstString(Numerical),
    DupLastString(Numerical),
    Append(u8),
    Prefix(u8),
    OmitRange(Numerical, Numerical),
    InsertChar(Numerical, u8),
    Overstrike(Numerical, u8),
    Extract(Numerical, Numerical),
    ReplaceAll(CharSelector, u8),
    Truncate(Numerical),
    InsertString(Numerical, Vec<u8>),
    ExtractInsert(Numerical, Numerical, Numerical),
    MemoryAssign(UserVar, Numerical, Numerical), // untested
                                                 // MISSING
                                                 // TitleSep - eX - hashcat only
}

#[allow(dead_code)]
fn rand_commandrule<T: rand::Rng>(rng: &mut T) -> CommandRule {
    use CommandRule::*;
    match rng.gen_range(0, 29) {
        0 => ToLower,
        1 => ToUpper,
        2 => Capitalize,
        3 => ToggleAll,
        4 => ShiftAll,
        5 => LowerVowelsUpperConsonants,
        6 => ShiftAllKeyboardRight,
        7 => ShiftAllKeyboardLeft,
        8 => Reverse,
        9 => Duplicate,
        10 => Reflect,
        11 => RotLeft,
        12 => RotRight,
        13 => SwapFirstTwo,
        14 => SwapLastTwo,
        15 => AppendMemory,
        16 => PrependMemory,
        17 => DupeAllChar,
        18 => Pluralize,
        19 => PastTense,
        20 => Genitive,
        21 => DeleteFirst,
        22 => DeleteLast,
        23 => Memorize,
        24 => ToggleCase(rand_numerical(rng)),
        25 => ToggleShift(rand_numerical(rng)),
        26 => DeleteAt(rand_numerical(rng)),
        27 => PurgeAll(rand_charselector(rng)),
        28 => TitleCase(rand_charselector(rng)),
        29 => DupWordNTimes(rand_numerical(rng)),
        30 => BitshiftRight(rand_numerical(rng)),
        31 => BitshiftLeft(rand_numerical(rng)),
        32 => Swap(rand_numerical(rng), rand_numerical(rng)),
        33 => Increment(rand_numerical(rng)),
        34 => Decrement(rand_numerical(rng)),
        35 => DupeFirstChar(rand_numerical(rng)),
        36 => DupeLastChar(rand_numerical(rng)),
        37 => ReplaceWithNext(rand_numerical(rng)),
        38 => ReplaceWithPrior(rand_numerical(rng)),
        39 => DupFirstString(rand_numerical(rng)),
        40 => DupLastString(rand_numerical(rng)),
        41 => OmitRange(rand_numerical(rng), rand_numerical(rng)),
        42 => InsertChar(rand_numerical(rng), rng.gen()),
        43 => Overstrike(rand_numerical(rng), rng.gen()),
        44 => Extract(rand_numerical(rng), rand_numerical(rng)),
        45 => ReplaceAll(rand_charselector(rng), rng.gen()),
        46 => Truncate(rand_numerical(rng)),
        47 => ExtractInsert(
            rand_numerical(rng),
            rand_numerical(rng),
            rand_numerical(rng),
        ),
        _ => MemoryAssign(rand_uservar(rng), rand_numerical(rng), rand_numerical(rng)), // untested
    }
}

#[allow(dead_code)]
pub fn rand_commandrules() -> Vec<CommandRule> {
    use rand::Rng;
    let mut o = Vec::new();
    let mut rng = rand::thread_rng();
    let n: u8 = rng.gen();
    let ln = if n < 100 {
        1
    } else if n < 150 {
        2
    } else if n < 200 {
        3
    } else if n < 230 {
        4
    } else {
        5
    };

    for _ in 0..ln {
        o.push(rand_commandrule(&mut rng));
    }

    o
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd)]
pub enum Rule {
    Reject(RejectRule),
    Command(CommandRule),
}

pub struct RuleEnv {
    memory: Vec<u8>,
    userlen: HashMap<UserVar, u8>,
    savedlen: u8,
    lastfound: u8,
}

fn eval_length(nm: &Numerical, env: &RuleEnv) -> u8 {
    use Numerical::*;
    match nm {
        Val(x) => *x,
        MinLen => 0,
        MinLenMinus1 => 0,
        MinLenPlus1 => 1,
        MaxLen => 254,
        MaxLenMinus1 => 253,
        MaxLenPlus1 => 255,
        SavedLen(uvar) => *env.userlen.get(uvar).unwrap_or(&0),
        WordLen => env.savedlen,
        WordLastCharPos => {
            if env.savedlen == 0 {
                0
            } else {
                env.savedlen - 1
            }
        }
        Infinite => 255,
        LastFound => env.lastfound,
    }
}

fn check_class(c: u8, cl: &CharClass) -> bool {
    use CharClass::*;
    match cl {
        CCVowels => CHARS_VOWELS.contains(&c),
        CCConsonants => CHARS_CONSONANTS.contains(&c),
        CCWhitespace => CHARS_WHITESPACE.contains(&c),
        CCPunctuation => CHARS_PUNCTUATION.contains(&c),
        CCSymbols => CHARS_SPECIALS.contains(&c),
        CCLower => (b'a'..=b'z').contains(&c),
        CCUpper => (b'A'..=b'Z').contains(&c),
        CCDigits => (b'0'..=b'9').contains(&c),
        CCLetters => (b'a'..=b'z').contains(&c) || (b'A'..=b'Z').contains(&c),
        CCAlphaNum => {
            (b'a'..=b'z').contains(&c) || (b'A'..=b'Z').contains(&c) || (b'0'..=b'9').contains(&c)
        }
        CCControl => CHARS_CONTROL_ASCII.contains(&c),
        CCAll => true,
        CCBit8 => c > 127,
        CCSingle(x) => c == *x,
    }
}

fn in_class(c: u8, cl: &CharSelector) -> bool {
    use CharSelector::*;
    match cl {
        OneOf(cl_) => check_class(c, cl_),
        NoneOf(cl_) => !check_class(c, cl_),
    }
}

fn must_reject(rj: &RejectRule, word: &[u8], env: &RuleEnv) -> bool {
    use RejectRule::*;
    match rj {
        UnlessWordLengthLessThan(n) => word.len() as u8 <= eval_length(n, env),
        UnlessWordLengthMoreThan(n) => word.len() as u8 >= eval_length(n, env),
        UnlessWordLengthIs(n) => word.len() as u8 == eval_length(n, env),
        IfContain(cl) => word.iter().all(|c| in_class(*c, cl)),
        UnlessContain(cl) => !word.iter().all(|c| in_class(*c, cl)),
        UnlessCharAt(n, cl) => word
            .get(eval_length(n, env) as usize)
            .map(|c| in_class(*c, cl))
            .unwrap_or(true),
        UnlessFirstChar(cl) => word.first().map(|c| in_class(*c, cl)).unwrap_or(true),
        UnlessLastChar(cl) => word.last().map(|c| in_class(*c, cl)).unwrap_or(true),
        UnlessAtLeastNTimes(n, cl) => {
            word.iter().filter(|c| in_class(**c, cl)).count() >= eval_length(n, env) as usize
        }
        _ => false,
    }
}

fn toggle(tbl: [u8; 256], c: &mut u8) {
    let x = tbl[*c as usize];
    if x != 0 {
        *c = x;
    }
}

fn run_conv(cur: &mut Vec<u8>, tbl: [u8; 256]) {
    for c in cur.iter_mut() {
        let x = tbl[*c as usize];
        if x != 0 {
            *c = x;
        }
    }
}

fn is_vowel_no_y(x: char) -> bool {
    x == 'a' || x == 'e' || x == 'i' || x == 'o' || x == 'u'
}

fn is_bgp(x: char) -> bool {
    x == 'b' || x == 'g' || x == 'p'
}

pub fn mutate(word: &[u8], rules: &[Rule]) -> Option<Vec<u8>> {
    let mut env = RuleEnv {
        memory: word.to_vec(),
        userlen: HashMap::new(),
        savedlen: word.len() as u8,
        lastfound: 0,
    };
    let convs = &super::CONVS;
    let mut cur = word.to_vec();
    for r in rules {
        let curlength = cur.len();
        if curlength == 0 {
            return None;
        }
        match r {
            Rule::Reject(rj) => {
                if must_reject(rj, &cur, &env) {
                    return None;
                }
            }
            Rule::Command(cmd) => {
                use CommandRule::*;
                match cmd {
                    Noop => (),
                    ToLower => cur.make_ascii_lowercase(),
                    ToUpper => cur.make_ascii_uppercase(),
                    Capitalize => {
                        cur.make_ascii_lowercase();
                        if let Some(c) = cur.first_mut() {
                            (*c).make_ascii_uppercase()
                        }
                    }
                    InvertCapitalize => {
                        cur.make_ascii_uppercase();
                        if let Some(c) = cur.first_mut() {
                            (*c).make_ascii_lowercase()
                        }
                    }
                    ToggleAll => run_conv(&mut cur, convs.cinvert),
                    ShiftAll => run_conv(&mut cur, convs.cshift),
                    LowerVowelsUpperConsonants => run_conv(&mut cur, convs.cvowels),
                    ShiftAllKeyboardRight => run_conv(&mut cur, convs.cright),
                    ShiftAllKeyboardLeft => run_conv(&mut cur, convs.cleft),
                    ToggleCase(p1) => cur
                        .get_mut(eval_length(p1, &env) as usize)
                        .map_or((), |c| toggle(convs.cinvert, c)),
                    Reverse => cur.reverse(),
                    Duplicate => cur.extend(cur.clone()),
                    Reflect => {
                        let mut v = cur.clone();
                        v.reverse();
                        cur.extend(v);
                    }
                    RotLeft => cur.rotate_left(1),
                    RotRight => cur.rotate_right(1),
                    Append(c) => cur.push(*c),
                    Prefix(c) => cur.insert(0, *c),
                    InsertString(n, s) => {
                        let pos = eval_length(n, &env) as usize;
                        let after = cur.split_off(pos);
                        let middle = s.clone();
                        cur.extend(middle);
                        cur.extend(after);
                    }
                    Truncate(p) => cur.truncate(eval_length(p, &env) as usize),
                    DeleteFirst => {
                        let _ = cur.remove(0);
                    }
                    DeleteLast => {
                        let _ = cur.pop();
                    }
                    DeleteAt(p) => {
                        let pos = eval_length(p, &env) as usize;
                        if curlength <= pos {
                            return None;
                        }
                        let _ = cur.remove(pos);
                    }
                    Extract(p, l) => {
                        let pos = eval_length(p, &env) as usize;
                        let len = eval_length(l, &env) as usize;
                        if pos >= curlength || pos + len >= curlength - 1 {
                            return None;
                        }
                        let rng = cur[pos..pos + len].to_vec();
                        cur = rng;
                    }
                    InsertChar(p, c) => {
                        let pos = eval_length(p, &env) as usize;
                        if curlength <= pos {
                            return None;
                        }
                        cur.insert(pos, *c);
                    }
                    Overstrike(p, c) => {
                        let pos = eval_length(p, &env) as usize;
                        if curlength <= pos {
                            return None;
                        }
                        cur[pos] = *c;
                    }
                    Memorize => env.memory = cur.clone(),
                    ExtractInsert(pe, l, pi) => {
                        let pe_ = eval_length(pe, &env) as usize;
                        let l_ = eval_length(l, &env) as usize;
                        let pi_ = eval_length(pi, &env) as usize;
                        match env.memory.get(pe_..(pe_ + l_)) {
                            None => (),
                            Some(to_insert) => {
                                let tail = cur.split_off(pi_);
                                cur.extend(to_insert);
                                cur.extend(tail);
                            }
                        }
                    }
                    ReplaceAll(cl, cr) => {
                        for c in cur.iter_mut() {
                            if in_class(*c, cl) {
                                *c = *cr
                            };
                        }
                    }
                    PurgeAll(cl) => cur.retain(|&c| !in_class(c, cl)),
                    DupWordNTimes(n) => {
                        let initial = cur.clone();
                        for _ in 0..(eval_length(n, &env)) {
                            cur.extend(initial.clone());
                        }
                    }
                    SwapFirstTwo => {
                        if curlength < 2 {
                            return None;
                        }
                        cur.swap(0, 1);
                    }
                    SwapLastTwo => {
                        if let Some(last) = cur.pop() {
                            if let Some(prev) = cur.pop() {
                                cur.push(last);
                                cur.push(prev);
                            } else {
                                return None;
                            };
                        } else {
                            return None;
                        }
                    }
                    Swap(p1, p2) => {
                        let p1_ = eval_length(p1, &env) as usize;
                        let p2_ = eval_length(p2, &env) as usize;
                        if curlength <= p1_ || curlength <= p2_ {
                            return None;
                        }
                        cur.swap(p1_, p2_);
                    }
                    Increment(p) => {
                        let pos = eval_length(p, &env) as usize;
                        if curlength > pos {
                            cur[pos] += 1;
                        }
                    }
                    Decrement(p) => {
                        let pos = eval_length(p, &env) as usize;
                        if curlength <= pos {
                            return None;
                        }
                        cur[pos] -= 1;
                    }
                    AppendMemory => cur.extend(env.memory.clone()),
                    PrependMemory => {
                        let mut tmp = env.memory.clone();
                        tmp.append(&mut cur);
                        cur = tmp;
                    }
                    DupeFirstChar(n) => {
                        if curlength == 0 {
                            return None;
                        }
                        let c0: u8 = cur[0];
                        let count = eval_length(n, &env) as usize;
                        let mut nv = Vec::new();
                        for _ in 0..count {
                            nv.push(c0);
                        }
                        nv.append(&mut cur);
                        cur = nv;
                    }
                    DupeLastChar(n) => {
                        if curlength == 0 {
                            return None;
                        }
                        let lst: u8 = cur[curlength - 1];
                        let count = eval_length(n, &env) as usize;
                        for _ in 0..count {
                            cur.push(lst);
                        }
                    }
                    DupeAllChar => {
                        let mut nv = Vec::new();
                        for c in cur.iter() {
                            nv.push(*c);
                            nv.push(*c);
                        }
                        cur = nv;
                    }
                    BitshiftLeft(p) => {
                        let pos = eval_length(p, &env) as usize;
                        if curlength <= pos {
                            return None;
                        }
                        cur[pos] <<= 1;
                    }
                    BitshiftRight(p) => {
                        let pos = eval_length(p, &env) as usize;
                        if curlength <= pos {
                            return None;
                        }
                        cur[pos] >>= 1;
                    }
                    ReplaceWithNext(p) => {
                        let pos = eval_length(p, &env) as usize;
                        let nxt = pos + 1;
                        if curlength <= nxt {
                            return None;
                        }
                        cur[pos] = cur[nxt];
                    }
                    ReplaceWithPrior(p) => {
                        let pos = eval_length(p, &env) as usize;
                        if curlength <= 1 || pos == 0 || pos >= curlength {
                            return None;
                        }
                        let nxt = pos - 1;
                        cur[pos] = cur[nxt];
                    }
                    DupFirstString(n) => {
                        let sz = eval_length(n, &env) as usize;
                        if sz >= curlength {
                            return None;
                        }
                        let mut nv = Vec::new();
                        nv.extend(&cur[..sz]);
                        nv.append(&mut cur);
                        cur = nv;
                    }
                    DupLastString(n) => {
                        let sz = eval_length(n, &env) as usize;
                        let cs = curlength;
                        if cs < sz {
                            return None;
                        }
                        let mut nv = cur.clone();
                        let idx = cs - sz;
                        nv.extend(&cur[idx..]);
                        cur = nv;
                    }
                    OmitRange(p, l) => {
                        let pos = eval_length(p, &env) as usize;
                        let ln = eval_length(l, &env) as usize;
                        if pos >= curlength {
                            return None;
                        }
                        if pos + ln >= curlength {
                            cur.truncate(pos);
                        } else {
                            let mut after = cur.split_off(pos);
                            let tail = after.split_off(ln);
                            cur.extend(tail);
                        }
                    }
                    MemoryAssign(_v, _p, _l) => return None, // TODO
                    Pluralize => {
                        if curlength < 2 {
                            return None;
                        }
                        let last_letter = cur[curlength - 1] as char;
                        let prev_letter = cur[curlength - 2] as char;
                        if last_letter == 's'
                            || last_letter == 'x'
                            || last_letter == 'z'
                            || (last_letter == 'h' && (prev_letter == 'c' || prev_letter == 's'))
                        {
                            cur.push(b'e');
                        } else if last_letter == 'f' && prev_letter != 'f' {
                            cur[curlength - 1] = b'v';
                            cur.push(b'e');
                        } else if last_letter == 'e' && prev_letter == 'f' {
                            cur[curlength - 2] = b'v';
                            cur[curlength - 1] = b'e';
                        } else if last_letter == 'y' && !is_vowel_no_y(prev_letter) {
                            cur[curlength - 1] = b'i';
                            cur.push(b'e');
                        }
                        cur.push(b's');
                    }
                    PastTense => {
                        if curlength < 3 {
                            return None;
                        }
                        let raw_last_letter = cur[curlength - 1];
                        let mut last_letter = raw_last_letter as char;
                        let prev_letter = cur[curlength - 2] as char;
                        if last_letter != 'd' || prev_letter != 'e' {
                            if last_letter == 'y' {
                                last_letter = 'i';
                                cur[curlength - 1] = last_letter as u8;
                            } else if is_bgp(last_letter) && !is_bgp(prev_letter) {
                                cur.push(raw_last_letter);
                            }
                            if last_letter != 'e' {
                                cur.push(b'e');
                            }
                            cur.push(b'd');
                        }
                    }
                    Genitive => {
                        if curlength < 3 {
                            return None;
                        }
                        let raw_last_letter = cur[curlength - 1];
                        let last_letter = raw_last_letter as char;
                        let prev_letter = cur[curlength - 2] as char;
                        let pprev_letter = cur[curlength - 3] as char;
                        if last_letter != 'g' || prev_letter != 'n' || pprev_letter != 'i' {
                            if is_vowel_no_y(last_letter) {
                                cur[curlength - 1] = b'i';
                            } else {
                                if is_bgp(last_letter) && !is_bgp(prev_letter) {
                                    cur.push(raw_last_letter);
                                }
                                cur.push(b'i');
                            }
                            cur.push(b'n');
                            cur.push(b'g');
                        }
                    }
                    TitleCase(cl) => {
                        let mut title = true;
                        for c in cur.iter_mut() {
                            if title {
                                toggle(convs.cinvert, c)
                            }
                            title = in_class(*c, cl);
                        }
                    }
                    ToggleShift(p1) => cur
                        .get_mut(eval_length(p1, &env) as usize)
                        .map_or((), |c| toggle(convs.cshift, c)),
                }
            }
        }
    }
    Some(cur)
}

pub fn show_command(cmd: &CommandRule, hashcat_mode: bool) -> Option<String> {
    use CommandRule::*;
    let hashcat_only = |s: String| if hashcat_mode { Some(s) } else { None };
    let john_only = |s: String| if hashcat_mode { None } else { Some(s) };
    match cmd {
        // common
        Noop => Some(String::from(":")),
        ToLower => Some(String::from("l")),
        ToUpper => Some(String::from("u")),
        Capitalize => Some(String::from("c")),
        InvertCapitalize => Some(String::from("C")),
        ToggleAll => Some(String::from("t")),
        ToggleCase(n) => Some(String::from("T") + show_num(n).as_str()),
        Reverse => Some(String::from("r")),
        Duplicate => Some(String::from("d")),
        DupWordNTimes(n) => hashcat_only(String::from("p") + show_num(n).as_str()),
        Reflect => Some(String::from("f")),
        RotLeft => Some(String::from("{")),
        RotRight => Some(String::from("}")),
        Append(x) => Some(String::from("$") + show_char(*x).as_str()),
        DeleteFirst => Some(if hashcat_mode {
            String::from("[")
        } else {
            String::from("\\[")
        }),
        DeleteLast => Some(if hashcat_mode {
            String::from("]")
        } else {
            String::from("\\]")
        }),
        DeleteAt(n) => Some(String::from("D") + show_num(n).as_str()),
        Extract(n, m) => Some(String::from("x") + show_num(n).as_str() + show_num(m).as_str()),
        OmitRange(n, m) => Some(String::from("O") + show_num(n).as_str() + show_num(m).as_str()),
        InsertChar(n, c) => Some(String::from("i") + show_num(n).as_str() + show_char(*c).as_str()),
        Overstrike(n, c) => Some(String::from("o") + show_num(n).as_str() + show_char(*c).as_str()),
        Truncate(n) => Some(String::from("'") + show_num(n).as_str()),
        ReplaceAll(cc, c) => {
            Some(String::from("s") + show_cs(cc).as_str() + show_char(*c).as_str())
        }
        PurgeAll(cc) => Some(String::from("@") + show_cs(cc).as_str()),
        DupeFirstChar(n) => Some(String::from("z") + show_num(n).as_str()),
        DupeLastChar(n) => Some(String::from("Z") + show_num(n).as_str()),
        DupeAllChar => Some(String::from("q")),
        ExtractInsert(n, m, o) => Some(
            String::from("X") + show_num(n).as_str() + show_num(m).as_str() + show_num(o).as_str(),
        ),
        AppendMemory => Some(String::from("4")),
        PrependMemory => Some(String::from("6")),
        Memorize => Some(String::from("M")),
        BitshiftLeft(n) => hashcat_only(String::from("L") + show_num(n).as_str()),
        BitshiftRight(n) => hashcat_only(String::from("R") + show_num(n).as_str()),
        SwapFirstTwo => hashcat_only(String::from("k")),
        SwapLastTwo => hashcat_only(String::from("K")),
        Swap(n, m) => hashcat_only(String::from("*") + show_num(n).as_str() + show_num(m).as_str()),
        Increment(n) => hashcat_only(String::from("+") + show_num(n).as_str()),
        Decrement(n) => hashcat_only(String::from("-") + show_num(n).as_str()),
        ReplaceWithNext(n) => hashcat_only(String::from(".") + show_num(n).as_str()),
        ReplaceWithPrior(n) => hashcat_only(String::from(",") + show_num(n).as_str()),
        DupFirstString(n) => hashcat_only(String::from("y") + show_num(n).as_str()),
        DupLastString(n) => hashcat_only(String::from("Y") + show_num(n).as_str()),

        // john only
        TitleCase(cc) => john_only(String::from("E") + show_cs(cc).as_str()),
        ShiftAllKeyboardLeft => john_only(String::from("L")),
        ShiftAllKeyboardRight => john_only(String::from("R")),
        ShiftAll => john_only(String::from("S")),
        LowerVowelsUpperConsonants => john_only(String::from("V")),
        ToggleShift(n) => john_only(String::from("W") + show_num(n).as_str()),
        Prefix(x) => john_only(String::from("^") + show_char(*x).as_str()),
        InsertString(n, s) => Some(
            // compatibility mode for Hashcat
            if hashcat_mode {
                let mut o = String::new();
                match n {
                    Numerical::Val(0) => {
                        for c in s.iter().rev() {
                            o.push('^');
                            o.push_str(show_char(*c).as_str());
                        }
                    }
                    Numerical::Infinite => {
                        for c in s.iter() {
                            o.push('$');
                            o.push_str(show_char(*c).as_str());
                        }
                    }
                    _ => {
                        // this should not happen as InsertString rules are not generated, and can
                        // only be caused by the worker_logic command.
                        println!("unhandled command: {:?}", cmd);
                        o = String::from("UNHANDLED");
                    }
                }
                o
            } else {
                String::from("A") + show_num(n).as_str() + show_string(s).as_str()
            },
        ),
        Pluralize => john_only(String::from("p")),
        PastTense => john_only(String::from("P")),
        Genitive => john_only(String::from("I")),
        MemoryAssign(uv, n, m) => Some(
            String::from("v")
                + show_uservar(uv).as_str()
                + show_num(n).as_str()
                + show_num(m).as_str(),
        ),
    }
}

fn support_commandrule(r: &CommandRule) -> ToolSupport {
    use CommandRule::*;
    match r {
        Extract(Numerical::Val(_), Numerical::Val(_))
        | Swap(Numerical::Val(_), Numerical::Val(_))
        | ToggleCase(Numerical::Val(_))
        | Truncate(Numerical::Val(_))
        | DeleteAt(Numerical::Val(_))
        | Increment(Numerical::Val(_))
        | Decrement(Numerical::Val(_))
        | BitshiftRight(Numerical::Val(_))
        | BitshiftLeft(Numerical::Val(_))
        | DupeFirstChar(Numerical::Val(_))
        | DupeLastChar(Numerical::Val(_))
        | ReplaceWithNext(Numerical::Val(_))
        | ReplaceWithPrior(Numerical::Val(_))
        | DupFirstString(Numerical::Val(_))
        | DupLastString(Numerical::Val(_))
        | InsertChar(Numerical::Val(_), _)
        | Overstrike(Numerical::Val(_), _)
        | OmitRange(Numerical::Val(_), Numerical::Val(_)) => ToolSupport::Both,
        ShiftAllKeyboardLeft
        | ShiftAllKeyboardRight
        | ShiftAll
        | LowerVowelsUpperConsonants
        | ToggleShift(_)
        | Prefix(_)
        | InsertString(_, _)
        | Pluralize
        | PastTense
        | Genitive
        | TitleCase(_)
        | Extract(_, _)
        | Swap(_, _)
        | ToggleCase(_)
        | Truncate(_)
        | DeleteAt(_)
        | Increment(_)
        | Decrement(_)
        | BitshiftRight(_)
        | BitshiftLeft(_)
        | DupeFirstChar(_)
        | DupeLastChar(_)
        | ReplaceWithNext(_)
        | ReplaceWithPrior(_)
        | DupFirstString(_)
        | DupLastString(_)
        | OmitRange(_, _)
        | InsertChar(_, _)
        | Overstrike(_, _)
        | MemoryAssign(_, _, _) => ToolSupport::JtR,
        _ => ToolSupport::Both,
    }
}

pub fn john_rule(r: &Rule) -> bool {
    match r {
        Rule::Reject(_) => true,
        Rule::Command(r) => support_commandrule(r) != ToolSupport::Hashcat,
    }
}

pub fn hashcat_rule(r: &Rule) -> bool {
    match r {
        Rule::Reject(_) => true,
        Rule::Command(r) => support_commandrule(r) != ToolSupport::JtR,
    }
}

pub fn show_num(n: &Numerical) -> String {
    use Numerical::*;
    match n {
        Val(n) => {
            if *n > 10 {
                ((*n - 10 + b'A') as char).to_string()
            } else {
                ((*n + b'0') as char).to_string()
            }
        }
        MinLen => String::from("#"),
        MinLenMinus1 => String::from("@"),
        MinLenPlus1 => String::from("$"),
        MaxLen => String::from("*"),
        MaxLenMinus1 => String::from("-"),
        MaxLenPlus1 => String::from("+"),
        SavedLen(uv) => show_uservar(uv),
        WordLen => String::from("l"),
        WordLastCharPos => String::from("m"),
        LastFound => String::from("p"),
        Infinite => String::from("z"),
    }
}

pub fn show_char(c: u8) -> String {
    if (b'0'..=b'9').contains(&c) || (b'A'..=b'Z').contains(&c) || (b'a'..=b'z').contains(&c) {
        let mut o = String::new();
        o.push(c as char);
        return o;
    }
    let h = format!("{:X}", c);
    let mut o = String::from("\\x");
    if h.len() == 1 {
        o.push('0');
    }
    o += h.as_str();
    o
}

pub fn show_string(x: &[u8]) -> String {
    let mut o = String::new();
    let msep = STR_SEPARATORS.iter().find(|&c| !x.contains(c));
    match msep {
        None => panic!("Should not happen, did not find a separator"),
        Some(sep) => {
            o.push(*sep as char);
            for c in x {
                o.push(*c as char);
            }
            o.push(*sep as char);
        }
    }
    o
}

pub fn show_uservar(x: &UserVar) -> String {
    use UserVar::*;
    String::from(match x {
        UVA => "a",
        UVB => "b",
        UVC => "c",
        UVD => "d",
        UVE => "e",
        UVF => "f",
        UVG => "g",
        UVH => "h",
        UVI => "i",
        UVJ => "j",
        UVK => "k",
    })
}

pub fn show_cc(cs: &CharClass) -> String {
    use CharClass::*;
    match cs {
        CCVowels => String::from("?v"),
        CCConsonants => String::from("?c"),
        CCWhitespace => String::from("?w"),
        CCPunctuation => String::from("?p"),
        CCSymbols => String::from("?s"),
        CCLower => String::from("?l"),
        CCUpper => String::from("?u"),
        CCDigits => String::from("?d"),
        CCLetters => String::from("?l"),
        CCAlphaNum => String::from("?x"),
        CCControl => String::from("?o"),
        CCAll => String::from("?z"),
        CCBit8 => String::from("?b"),
        CCSingle(x) => show_char(*x),
    }
}

pub fn show_cs(cs: &CharSelector) -> String {
    let mut o = String::new();

    let cc = match cs {
        CharSelector::OneOf(x) => x,
        CharSelector::NoneOf(x) => {
            o += "!";
            x
        }
    };
    o + show_cc(cc).as_str()
}

pub fn show_reject(rej: &RejectRule) -> String {
    use RejectRule::*;
    fn pairn(a: &str, b: String) -> String {
        String::from(a) + b.as_str()
    }
    match rej {
        Noop => String::from("-:"),
        UnlessCaseSensitive => String::from("-c"),
        Unless8bits => String::from("-8"),
        UnlessSplit => String::from("-s"),
        UnlessWordPairs => String::from("-p"),
        UnlessUtf8 => String::from("-u"),
        IfUtf8 => String::from("-U"),
        UnlessSupportedLengthOrLonger(n) => pairn("->", show_num(n)),
        UnlessSupportedLengthOrShorted(n) => pairn("-<", show_num(n)),
        UnlessWordLengthLessThan(n) => pairn("<", show_num(n)),
        UnlessWordLengthMoreThan(n) => pairn(">", show_num(n)),
        UnlessWordLengthIs(n) => pairn("_", show_num(n)),
        UnlessValidAfterAdding(n) => pairn("a", show_num(n)),
        UnlessValidAfterRemoving(n) => pairn("b", show_num(n)),
        IfContain(cc) => pairn("!", show_cs(cc)),
        UnlessContain(cc) => pairn("/", show_cs(cc)),
        UnlessCharAt(n, cc) => String::from("=") + show_num(n).as_str() + show_cs(cc).as_str(),
        UnlessFirstChar(cc) => pairn("(", show_cs(cc)),
        UnlessLastChar(cc) => pairn(")", show_cs(cc)),
        UnlessAtLeastNTimes(n, cc) => {
            String::from("%") + show_num(n).as_str() + show_cs(cc).as_str()
        }
        UnlessValidUtf8 => String::from("U"),
        RejectTheWordUnlessDifferent => String::from("Q"),
    }
}

pub fn show_rule(rule: &Rule, hashcat_mode: bool) -> Option<String> {
    match rule {
        Rule::Command(cmd) => show_command(cmd, hashcat_mode),
        Rule::Reject(rej) => Some(show_reject(rej)),
    }
}

pub fn show_rules(rules: &[Rule], hashcat_mode: bool) -> Option<String> {
    rules.iter().map(|r| show_rule(r, hashcat_mode)).collect()
}

#[allow(dead_code)]
pub fn show_commands(rules: &[CommandRule], hashcat_mode: bool) -> Option<String> {
    rules
        .iter()
        .map(|r| show_command(r, hashcat_mode))
        .collect()
}

pub fn genmutate() -> Vec<Vec<Rule>> {
    use CharClass::*;
    use CharSelector::*;
    use CommandRule::*;
    use Numerical::*;
    use Rule::Command;
    let basecmds = vec![
        Noop,
        ToLower,
        ToUpper,
        Capitalize,
        ToggleAll,
        ShiftAll,
        LowerVowelsUpperConsonants,
        ShiftAllKeyboardRight,
        ShiftAllKeyboardLeft,
        Reverse,
        Duplicate,
        Reflect,
        Pluralize,
        PastTense,
        Genitive,
        DupeAllChar,
        DupWordNTimes(Val(3)),
        DupWordNTimes(Val(4)),
        TitleCase(OneOf(CCPunctuation)),
        TitleCase(OneOf(CCWhitespace)),
        ReplaceAll(OneOf(CCSingle(b'q')), b'Q'),
        ReplaceAll(OneOf(CCSingle(b'y')), b'i'),
        ReplaceAll(OneOf(CCSingle(b'i')), b'y'),
        ReplaceAll(OneOf(CCSingle(b'i')), b'!'),
    ];
    let leetrules = [
        ReplaceAll(OneOf(CCSingle(b'a')), b'4'),
        ReplaceAll(OneOf(CCSingle(b'e')), b'3'),
        ReplaceAll(OneOf(CCSingle(b'i')), b'1'),
        ReplaceAll(OneOf(CCSingle(b'o')), b'0'),
        ReplaceAll(OneOf(CCSingle(b's')), b'5'),
        ReplaceAll(OneOf(CCSingle(b'A')), b'4'),
        ReplaceAll(OneOf(CCSingle(b'E')), b'3'),
        ReplaceAll(OneOf(CCSingle(b'I')), b'1'),
        ReplaceAll(OneOf(CCSingle(b'O')), b'0'),
        ReplaceAll(OneOf(CCSingle(b'S')), b'5'),
    ];
    let numericals = [
        Val(0),
        Val(1),
        Val(2),
        Val(3),
        Val(4),
        Val(5),
        Val(6),
        Val(7),
        Val(8),
        Val(9),
        WordLen,
        WordLastCharPos,
    ];

    let mut out = Vec::new();
    for cmd in basecmds {
        out.push(vec![Command(cmd)]);
    }
    let mut lr = Vec::new();
    for cmd in &leetrules {
        out.push(vec![Command(cmd.clone())]);
        lr.push(Command(cmd.clone()));
    }
    out.push(lr);

    let mut rl = Vec::new();
    let mut rr = Vec::new();
    let mut df = Vec::new();
    let mut dl = Vec::new();
    for _ in 0..4 {
        rl.push(Command(RotLeft));
        rr.push(Command(RotRight));
        df.push(Command(DeleteFirst));
        dl.push(Command(DeleteLast));
        out.push(rl.clone());
        out.push(rr.clone());
        out.push(df.clone());
        out.push(dl.clone());
    }

    for letter in b'a'..=b'z' {
        out.push(vec![Command(PurgeAll(OneOf(CCSingle(letter))))]);
    }
    for letter in b'A'..=b'Z' {
        out.push(vec![Command(PurgeAll(OneOf(CCSingle(letter))))]);
    }
    for letter in b'0'..=b'9' {
        out.push(vec![Command(PurgeAll(OneOf(CCSingle(letter))))]);
    }
    for n in numericals.iter() {
        out.push(vec![Command(ToggleCase(n.clone()))]);
        out.push(vec![Command(ToggleShift(n.clone()))]);
        out.push(vec![Command(Truncate(n.clone()))]);
        out.push(vec![Command(DeleteAt(n.clone()))]);
        out.push(vec![Command(Increment(n.clone()))]);
        out.push(vec![Command(Decrement(n.clone()))]);
        out.push(vec![Command(BitshiftRight(n.clone()))]);
        out.push(vec![Command(BitshiftLeft(n.clone()))]);
        out.push(vec![Command(DupeFirstChar(n.clone()))]);
        out.push(vec![Command(DupeLastChar(n.clone()))]);
        out.push(vec![Command(ReplaceWithNext(n.clone()))]);
        out.push(vec![Command(ReplaceWithPrior(n.clone()))]);
        out.push(vec![Command(DupFirstString(n.clone()))]);
        out.push(vec![Command(DupLastString(n.clone()))]);
        for m in numericals.iter() {
            out.push(vec![Command(Extract(n.clone(), m.clone()))]);
            out.push(vec![Command(Swap(n.clone(), m.clone()))]);
            out.push(vec![Command(OmitRange(n.clone(), m.clone()))]);
        }
        for c in CONV_SOURCE.as_bytes().iter() {
            out.push(vec![Command(InsertChar(n.clone(), *c))]);
            out.push(vec![Command(Overstrike(n.clone(), *c))]);
        }
    }

    /*
    ReplaceAll(CharSelector, u8),
    InsertString(Numerical, String),

    ExtractInsert(Numerical, Numerical, Numerical),
    PurgeAll(CharSelector),
    TitleCase(CharSelector),
    */

    out
}

#[cfg(test)]
mod mutate {
    use super::*;
    use std::str;
    use CharClass::*;
    use CharSelector::*;
    use CommandRule::*;
    use Numerical::*;

    static DEFPWD: &str = "aSQdqdf354gdrf;:;é&";

    fn mut_test(source_word: &str, commands: &[CommandRule], expected: &str) {
        let ssource = source_word.as_bytes();
        let mut nrules = Vec::new();
        for cmd in commands {
            nrules.push(Rule::Command(cmd.clone()));
        }
        let res = mutate(ssource, &nrules);
        match res {
            None => panic!("no results"),
            Some(r) => match str::from_utf8(&r) {
                Ok(actual) => assert_eq!(actual, expected),
                Err(fail) => panic!("{}", fail),
            },
        }
    }

    #[test]
    fn noop() {
        mut_test("lol", &[Noop], "lol");
    }
    #[test]
    fn tolower() {
        mut_test("lOl1", &[ToLower], "lol1");
    }
    #[test]
    fn toupper() {
        mut_test("lOl1", &[ToUpper], "LOL1");
    }
    #[test]
    fn capitalize() {
        mut_test("lOl1", &[ToUpper], "LOL1");
    }
    #[test]
    fn toggleall() {
        mut_test(DEFPWD, &[ToggleAll], "AsqDQDF354GDRF;:;é&");
    }
    #[test]
    fn dup_word_n_times() {
        mut_test("P@ss", &[DupWordNTimes(Val(2))], "P@ssP@ssP@ss");
    }
    #[test]
    fn bitshift_right() {
        mut_test("P@ss", &[BitshiftRight(Val(2))], "P@9s");
    }
    #[test]
    fn bitshift_left() {
        mut_test("P0ss", &[BitshiftLeft(Val(1))], "P`ss");
    }
    #[test]
    fn swap_first_two() {
        mut_test("P@ss", &[SwapFirstTwo], "@Pss");
    }
    #[test]
    fn swap_last_two() {
        mut_test("P@sS", &[SwapLastTwo], "P@Ss");
    }
    #[test]
    fn swap() {
        mut_test("P@sS", &[Memorize, Swap(Val(0), WordLastCharPos)], "S@sP");
    }
    #[test]
    fn increment() {
        mut_test("P@ss", &[Increment(Val(1))], "PAss");
    }
    #[test]
    fn decrement() {
        mut_test("P@ss", &[Decrement(Val(1))], "P?ss");
    }
    #[test]
    fn append_memory() {
        mut_test(
            "P@ss",
            &[ToUpper, Memorize, ToLower, AppendMemory],
            "p@ssP@SS",
        );
    }
    #[test]
    fn prepend_memory() {
        mut_test(
            "P@ss",
            &[ToUpper, Memorize, ToLower, PrependMemory],
            "P@SSp@ss",
        );
    }
    #[test]
    fn dupe_first_char() {
        mut_test("P@ss", &[DupeFirstChar(Val(2))], "PPP@ss");
    }
    #[test]
    fn dupe_last_char() {
        mut_test("P@sS", &[DupeLastChar(Val(2))], "P@sSSS");
    }
    #[test]
    fn dupe_all_char() {
        mut_test("P@sS", &[DupeAllChar], "PP@@ssSS");
    }
    #[test]
    fn reverse_t() {
        mut_test("Fred", &[Reverse], "derF");
    }
    #[test]
    fn duplicate() {
        mut_test("Fred", &[Duplicate], "FredFred");
    }
    #[test]
    fn reflect() {
        mut_test("Fred", &[Reflect], "FredderF");
    }
    #[test]
    fn rotl() {
        mut_test("jsmith", &[RotLeft], "smithj");
    }
    #[test]
    fn rotr() {
        mut_test("smithj", &[RotRight], "jsmith");
    }
    #[test]
    fn shiftall() {
        mut_test(DEFPWD, &[ShiftAll], "AsqDQDF#%$GDRF:;:é7");
    }
    #[test]
    fn rule_v() {
        mut_test(DEFPWD, &[LowerVowelsUpperConsonants], "aSQDQDF354GDRF;:;é&");
    }
    #[test]
    fn shift_k_r() {
        mut_test(DEFPWD, &[ShiftAllKeyboardRight], "sDWfwfg465hftg'\"'é*");
    }
    #[test]
    fn shift_k_l() {
        mut_test(DEFPWD, &[ShiftAllKeyboardLeft], "aAQsqsd243fsedlLlé^");
    }
    #[test]
    fn omit_range() {
        mut_test("012345678", &[OmitRange(Val(3), Val(4))], "01278");
    }
    #[test]
    fn replace_with_next() {
        mut_test("P@sS", &[ReplaceWithNext(Val(2))], "P@SS");
    }
    #[test]
    fn replace_with_prior() {
        mut_test("P@sS", &[ReplaceWithPrior(Val(2))], "P@@S");
    }
    #[test]
    fn duplicate_first() {
        mut_test("P@sS", &[DupFirstString(Val(2))], "P@P@sS");
    }
    #[test]
    fn duplicate_last() {
        mut_test("P@sS", &[DupLastString(Val(2))], "P@sSsS");
    }
    #[test]
    fn title_case() {
        mut_test("test word", &[TitleCase(OneOf(CCWhitespace))], "Test Word");
    }
    #[test]
    fn toggle_case() {
        mut_test(DEFPWD, &[ToggleCase(Val(6))], "aSQdqdF354gdrf;:;é&");
    }
    #[test]
    fn toggle_shift() {
        mut_test(DEFPWD, &[ToggleShift(Val(6))], "aSQdqdF354gdrf;:;é&");
    }
    #[test]
    fn insert_string() {
        mut_test(
            DEFPWD,
            &[InsertString(Val(3), vec![b'l', b'o', b'l'])],
            "aSQloldqdf354gdrf;:;é&",
        );
    }
    #[test]
    fn truncate() {
        mut_test(DEFPWD, &[Truncate(Val(6))], "aSQdqd");
    }
    #[test]
    fn pluralize() {
        let tests = vec![
            "loaf", "fox", "soyouz", "plus", "foX", "fish", "stitch", "stitah", "pufe", "paye",
            "july",
        ];
        let expected = vec![
            "loaves", "foxes", "soyouzes", "pluses", "foXs", "fishes", "stitches", "stitahs",
            "puves", "payes", "julies",
        ];
        for (&t, &e) in tests.iter().zip(expected.iter()) {
            mut_test(t, &[Pluralize], e);
        }
    }
    #[test]
    fn past() {
        let tests = vec!["bed", "beg", "ped", "poe", "pid"];
        let expected = vec!["bed", "begged", "ped", "poed", "pided"];
        for (&t, &e) in tests.iter().zip(expected.iter()) {
            mut_test(t, &[PastTense], e);
        }
    }
    #[test]
    fn genitive() {
        let tests = vec!["ping", "pang", "poo", "pan"];
        let expected = vec!["ping", "pangging", "poing", "paning"];
        for (&t, &e) in tests.iter().zip(expected.iter()) {
            mut_test(t, &[Genitive], e);
        }
    }
    #[test]
    fn append() {
        mut_test("Fred", &[Append(b'x')], "Fredx");
    }
    #[test]
    fn prefix() {
        mut_test("Fred", &[Prefix(b'x')], "xFred");
    }
    #[test]
    fn delete_first() {
        mut_test("Fred", &[DeleteFirst], "red");
    }
    #[test]
    fn delete_last() {
        mut_test("Fred", &[DeleteLast], "Fre");
    }
    #[test]
    fn extract_insert() {
        mut_test(
            "p@ssW0rd",
            &[ToLower, ExtractInsert(Val(4), Val(2), Val(8))],
            "p@ssw0rdW0",
        );
    }
    #[test]
    fn delete_at() {
        mut_test(DEFPWD, &[DeleteAt(Val(4))], "aSQddf354gdrf;:;é&");
    }
    #[test]
    fn extract() {
        mut_test(DEFPWD, &[Extract(Val(3), Val(5))], "dqdf3");
    }
    #[test]
    fn insertchar() {
        mut_test(DEFPWD, &[InsertChar(Val(3), b'K')], "aSQKdqdf354gdrf;:;é&");
    }
    #[test]
    fn overstrike() {
        mut_test(DEFPWD, &[Overstrike(Val(3), b'K')], "aSQKqdf354gdrf;:;é&");
    }
    #[test]
    fn replace_all() {
        mut_test(
            DEFPWD,
            &[ReplaceAll(OneOf(CCPunctuation), b'0')],
            "aSQdqdf354gdrf000é&",
        );
    }
    #[test]
    fn purge_all() {
        mut_test(
            DEFPWD,
            &[PurgeAll(OneOf(CCPunctuation))],
            "aSQdqdf354gdrfé&",
        );
    }
}

#[cfg(test)]
mod display {
    use super::*;
    use CommandRule::*;
    use Numerical::*;

    #[test]
    fn append_str() {
        assert_eq!(
            show_command(&InsertString(Val(0), Vec::from("lol".as_bytes())), false),
            Some("A0\"lol\"".to_string())
        );
    }

    #[test]
    fn append_str_del1() {
        assert_eq!(
            show_command(&InsertString(Val(0), Vec::from("lo\"l".as_bytes())), false),
            Some("A0'lo\"l'".to_string())
        );
    }
}
