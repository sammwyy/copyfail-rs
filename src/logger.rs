/// Logger abstraction to handle output levels and silent mode.
pub struct Logger {
    /// If true, all output except critical errors (via panic) will be suppressed.
    pub silent: bool,
}

impl Logger {
    /// Creates a new Logger instance.
    pub fn new(silent: bool) -> Self {
        Self { silent }
    }

    /// Logs an informational message to stdout.
    pub fn info(&self, msg: &str) {
        if !self.silent {
            println!("[+] {}", msg);
        }
    }

    /// Logs a detailed debug message to stdout.
    pub fn debug(&self, msg: &str) {
        if !self.silent {
            println!("[*] {}", msg);
        }
    }

    /// Logs an error message to stderr.
    pub fn error(&self, msg: &str) {
        if !self.silent {
            eprintln!("[-] Error: {}", msg);
        }
    }
}
