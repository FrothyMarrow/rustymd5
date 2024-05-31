use rustymd5::MD5Context;

fn main() {
    let message = "Fuck you MD5";
    let mut context = MD5Context::new();
    let hash = context.digest(message);
    println!("Input: {message}");
    println!("MD5 Hash: {hash}");
}
