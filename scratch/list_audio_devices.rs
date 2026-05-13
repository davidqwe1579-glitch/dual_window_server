use cpal::traits::{DeviceTrait, HostTrait};

fn main() {
    let host = cpal::default_host();
    println!("Default Host: {:?}", host.id());

    println!("\nOutput Devices:");
    if let Ok(devices) = host.output_devices() {
        for device in devices {
            if let Ok(name) = device.name() {
                println!("  - {}", name);
            }
        }
    }

    println!("\nInput Devices:");
    if let Ok(devices) = host.input_devices() {
        for device in devices {
            if let Ok(name) = device.name() {
                println!("  - {}", name);
            }
        }
    }

    if let Some(device) = host.default_output_device() {
        if let Ok(name) = device.name() {
            println!("\nDefault Output Device: {}", name);
        }
    } else {
        println!("\nNo Default Output Device found.");
    }
}
