use rustymd5::MD5Context;

fn main() {
    let key = "ckczppom";

    let mut secret = String::from(key);
    let mut context = MD5Context::new();

    for i in 0..u32::MAX {
        secret.push_str(&i.to_string());
        let hash = context.digest(&secret);

        if hash.starts_with("00000") {
            println!("Secret 1: {}", secret);

            if hash.starts_with("000000") {
                println!("Secret 2: {}", secret);
                break;
            }
        }

        let (temp, _) = secret.split_at(8);
        secret = temp.to_string();
        context.reset();
    }
}
