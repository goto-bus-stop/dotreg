use dotreg::read;

fn main() {
    match std::env::args().nth(1) {
        Some(path) => {
            let f = std::fs::File::open(path).unwrap();
            println!("{:?}", read(f).unwrap());
        }
        None => {
            eprintln!("usage: cargo run --example parse <filename>");
        }
    }
}
