const K: [u32; 64] = [
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
];

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const M: [usize; 64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8,
    13, 2, 7, 12, 5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2, 0, 7, 14, 5, 12, 3, 10, 1,
    8, 15, 6, 13, 4, 11, 2, 9,
];

const ABCD: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

struct MD5Context {
    buffer: [u32; 16],
    state: [u32; 4],
}

fn f(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (!b & d)
}

fn g(b: u32, c: u32, d: u32) -> u32 {
    (b & d) | (c & !d)
}

fn h(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

fn i(b: u32, c: u32, d: u32) -> u32 {
    c ^ (b | !d)
}

fn rotate_left(n: u32, s: u32) -> u32 {
    n << s | n >> (32 - s)
}

fn calculate_common(context: &mut MD5Context, m: u32, k: u32, s: u32, c: u32) {
    let af = context.state[0].wrapping_add(c);
    let maf = m.wrapping_add(af);
    let kmaf = k.wrapping_add(maf);
    let skmaf = rotate_left(kmaf, s);
    let bskmaf = skmaf.wrapping_add(context.state[1]);

    context.state[0] = context.state[3];
    context.state[3] = context.state[2];
    context.state[2] = context.state[1];
    context.state[1] = bskmaf;
}

fn ff(context: &mut MD5Context, m: u32, k: u32, s: u32) {
    let f = f(context.state[1], context.state[2], context.state[3]);
    calculate_common(context, m, k, s, f)
}

fn gg(context: &mut MD5Context, m: u32, k: u32, s: u32) {
    let g = g(context.state[1], context.state[2], context.state[3]);
    calculate_common(context, m, k, s, g)
}

fn hh(context: &mut MD5Context, m: u32, k: u32, s: u32) {
    let h = h(context.state[1], context.state[2], context.state[3]);
    calculate_common(context, m, k, s, h)
}

fn ii(context: &mut MD5Context, m: u32, k: u32, s: u32) {
    let i = i(context.state[1], context.state[2], context.state[3]);
    calculate_common(context, m, k, s, i)
}

fn u8_to_u32_array(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks(4)
        .map(|chunk| {
            let mut buf = [0u8; 4];
            buf.iter_mut()
                .zip(chunk)
                .for_each(|(b, &chunk_b)| *b = chunk_b);
            u32::from_ne_bytes(buf)
        })
        .collect()
}

fn md5_encode_message(context: &mut MD5Context, message: &str) {
    let mut encoded_message: Vec<u8> = message.into();
    encoded_message.push(0x80);

    let encoded_words = encoded_message.len().div_ceil(4);
    let message_bits = message.len() * 8;

    context.buffer[..encoded_words].copy_from_slice(u8_to_u32_array(&encoded_message).as_slice());
    context.buffer[14] = message_bits as u32;
    context.buffer[15] = (message_bits >> 32) as u32;
}

fn md5_transform(context: &mut MD5Context) {
    for i in 0..16 {
        ff(context, context.buffer[M[i]], K[i], S[i]);
    }

    for i in 16..32 {
        gg(context, context.buffer[M[i]], K[i], S[i]);
    }

    for i in 32..48 {
        hh(context, context.buffer[M[i]], K[i], S[i]);
    }

    for i in 48..64 {
        ii(context, context.buffer[M[i]], K[i], S[i]);
    }

    let result: [u32; 4] = [
        context.state[0].wrapping_add(ABCD[0]),
        context.state[1].wrapping_add(ABCD[1]),
        context.state[2].wrapping_add(ABCD[2]),
        context.state[3].wrapping_add(ABCD[3]),
    ];

    print!("MD5 Hash: ");

    result
        .iter()
        .flat_map(|word| word.to_ne_bytes())
        .for_each(|byte| print!("{:02x}", byte));

    println!();
}

fn md5_init() -> MD5Context {
    MD5Context {
        buffer: [0u32; 16],
        state: ABCD,
    }
}

fn md5_digest(message: &str) {
    let mut context = md5_init();
    md5_encode_message(&mut context, message);

    println!("Input: {}", message);

    md5_transform(&mut context);
}

fn main() {
    md5_digest("Fuck you MD5");
}

#[test]
fn test_bitwise_operations() {
    assert_eq!(f(0x89abcdef, 0xfedcba98, 0x76543210), 0xfedcba98);
    assert_eq!(g(0x2c34dfa2, 0xde1673be, 0x4b976282), 0x9c1453be);
    assert_eq!(h(0xd5071367, 0xc058ade2, 0x63c603d7), 0x7699bd52);
    assert_eq!(i(0x7d502063, 0x8b3d715d, 0x1de3a739), 0x746109ba);
    assert_eq!(rotate_left(0x1234abcd, 12), 0x4abcd123);
}
