#![feature(asm)]
#![cfg(any(target_arch = "x86_64"))]
use nix::sys::{ptrace::{attach, syscall}, wait::*};				// nix = "0.14.1"
use nix::unistd::Pid;
use std::{time, thread, path::Path, process::exit};

fn main() {
	let ppid: i32 = get_ppid();						// getpid() return value
	let cpid: i32 = do_fork();						// fork() return value

	if cpid == 0 {								// fork() returns 0 to the child process
		exec_shell(ppid);						// execute shellcode in the child process
	} else {								// fork() returns the child's pid to the parent
		start_tracer(cpid);						// execute start_tracer() as the parent process
	}
	exit(0);
}

fn get_ppid() -> i32 {
	let ppid: i32;
	unsafe {
		asm!("mov rax, 39"	:		:::"intel");		// getpid(void)
		asm!("syscall"		:"={rax}"(ppid)	:::"intel");		// save return value
	}
	return ppid
}

fn do_fork() -> i32 {
	let cpid: i32;
	unsafe {
		asm!("mov rax, 57"	:		:::"intel");		// fork(void)
		asm!("syscall"		:"={rax}"(cpid)	:::"intel");		// save return value
	}
	return cpid
}

fn exec_shell(ppid: i32) {							// this fn is called by the child thread
	thread::sleep(time::Duration::new(1, 0));				// before checking if the parent is still active, wait a second
	let ppid_path = format!("/proc/{}/maps", ppid);
	if Path::is_file(Path::new(&ppid_path)) {
		println!("[child]: spawning shell...");
	} else {
		println!("[child]: debugger detected, exiting...");
		exit(0)
	}
	unsafe {
		asm!("xor rax, rax"			::::"intel");
		asm!("push rax"				::::"intel");
		asm!("mov rdi, 0x68732f6e69622f2f"	::::"intel");		// hs/nib//
		asm!("push rdi"				::::"intel");
		asm!("mov rdi, rsp"			::::"intel");
		asm!("push rax"				::::"intel");
		asm!("push rdi"				::::"intel");
		asm!("mov rsi, rsp"			::::"intel");
		asm!("push rax"				::::"intel");
		asm!("mov rdx, rsp"			::::"intel");
		asm!("mov rax, 59"			::::"intel");		// int execve(const char *filename, char *const argv[], char *const envp[])
		asm!("syscall"				::::"intel");
		asm!("mov rax, 60"			::::"intel");		// void _exit(int status)
		asm!("mov rdi, 0"			::::"intel");
		asm!("syscall"				::::"intel");
	}
}

fn start_tracer(cpid: i32) {							// this fn is called by the parent process
	let pid = Pid::from_raw(cpid);
	let _res = match attach(pid) {
		Ok(_s)  => println!("[parent]: established tracing lock on child ({}), manually executing child thread...", cpid),
		Err(_e) => abort()
	};
	loop {  // within this loop, ptrace is used to manually execute the child thread, until it exits
		let _next_syscall = match syscall(pid) {
			Ok(_s)  => _s,
			Err(_e) => ()
		};
		let status: &str = match waitpid(pid, Some(<WaitPidFlag>::WSTOPPED)) {
			Ok(WaitStatus::Stopped(_, _sig))        => "ok",
			Ok(WaitStatus::PtraceEvent(_, _sig, _)) => "ok",
			Ok(WaitStatus::PtraceSyscall(_process)) => "ok",
			Ok(WaitStatus::Signaled(_, _sig, _))    => "ok",
			Ok(WaitStatus::Exited(_process, _))     => "exited",
			Ok(WaitStatus::Continued(_process))     => "ok",
			Ok(WaitStatus::StillAlive)              => "ok",
			Err(_e) => "exited"
		};
		if status == "exited" {
			break
		}
	}
}

fn abort() {
	println!("[parent]: failed to acquire tracer lock on child, exiting from parent process...");
	unsafe {
		asm!("mov rax, 60"      ::::"intel");                           // void _exit(int status)
		asm!("mov rdi, 0"       ::::"intel");
		asm!("syscall"          ::::"intel");
	}
}



