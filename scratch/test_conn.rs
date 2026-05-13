use std::net::{TcpStream, TcpListener};
use std::thread;
use std::time::Duration;

fn main() {
    let port = 9091;
    
    // Start a dummy listener (like the worker)
    thread::spawn(move || {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).unwrap();
        println!("Listener started on {}", port);
        loop {
            match listener.accept() {
                Ok((_stream, addr)) => println!("Accepted connection from {}", addr),
                Err(e) => println!("Accept error: {}", e),
            }
        }
    });

    thread::sleep(Duration::from_millis(500));

    // Try to connect (like the controller)
    println!("Connecting to 127.0.0.1:{}...", port);
    match TcpStream::connect(format!("127.0.0.1:{}", port)) {
        Ok(_) => println!("Connection successful!"),
        Err(e) => println!("Connection failed: {}", e),
    }

    // Try to connect to machine IP
    let machine_ip = "192.168.1.232";
    println!("Connecting to {}:{}...", machine_ip, port);
    match TcpStream::connect(format!("{}:{}", machine_ip, port)) {
        Ok(_) => println!("Connection successful!"),
        Err(e) => println!("Connection failed: {}", e),
    }
}
