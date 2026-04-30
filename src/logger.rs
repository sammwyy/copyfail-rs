pub struct Logger {
    pub silent: bool,
}

impl Logger {
    pub fn new(silent: bool) -> Self {
        Self { silent }
    }

    pub fn info(&self, msg: &str) {
        if !self.silent {
            println!("[+] {}", msg);
        }
    }

    pub fn warn(&self, msg: &str) {
        if !self.silent {
            println!("[!] {}", msg);
        }
    }

    pub fn error(&self, msg: &str) {
        if !self.silent {
            eprintln!("[-] Error: {}", msg);
        }
    }

    pub fn debug(&self, msg: &str) {
        if !self.silent {
            println!("[*] {}", msg);
        }
    }
}
