//! Safe terminal output that never panics (a broken pipe must not abort the
//! clipboard wipe) and never prints secrets.

macro_rules! say {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = writeln!(::std::io::stdout(), $($arg)*);
    }};
}

macro_rules! problem {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = writeln!(::std::io::stderr(), $($arg)*);
    }};
}

pub(crate) use {problem, say};
