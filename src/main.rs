use std::{
    io,
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use dns_lookup::lookup_host;
use icmp_socket::packet::{Icmpv4Packet, WithEchoRequest};
use icmp_socket::socket::{IcmpSocket, IcmpSocket4};
use icmp_socket::*;

fn str_to_v4ip(v: &str) -> io::Result<Ipv4Addr> {
    match v.parse() {
        Ok(r) => Ok(r),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidInput, e.to_string())),
    }
}
fn str_is_v4ip(s: &str) -> bool {
    let mut r = s.split(".");
    if r.clone().count() != 4 {
        return false;
    }
    r.all(|e| match e.parse::<u8>() {
        Ok(_) => true,
        Err(_) => false,
    })
}
fn main() -> Result<(), io::Error> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid arguments number",
        ));
    }
    let infinite = if args.contains(&"-t".to_string()) {
        true
    } else {
        false
    };
    let dest = &args[1];
    let dest_ip = if str_is_v4ip(dest) {
        dest.clone()
    } else {
        match lookup_host(dest) {
            Ok(r) => {
                if r.len() > 0 {
                    r[0].to_string()
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid hostname",
                    ));
                }
            }
            Err(e) => {
                let s = e.to_string();
                return Err(io::Error::new(io::ErrorKind::InvalidInput, s));
            }
        }
    };
    let mut socket = IcmpSocket4::try_from(str_to_v4ip("0.0.0.0")?)?;
    let mut sequence = 0u16;
    let payload: Vec<u8> = vec![
        0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20, 0x66, 0x6c, 0x65, 0x73, 0x68, 0x20, 0x77,
        0x6f, 0x75, 0x6e, 0x64, 0x20, 0x20, 0x74, 0x69, 0x73, 0x20, 0x62, 0x75, 0x74, 0x20, 0x61,
        0x20, 0x73, 0x63, 0x72, 0x61, 0x74, 0x63, 0x68, 0x20, 0x20, 0x6b, 0x6e, 0x69, 0x67, 0x68,
        0x74, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x6e, 0x69, 0x20, 0x20, 0x20,
    ];
	println!("PING {}: {} data bytes", dest, payload.len());
    loop {
        let packet = Icmpv4Packet::with_echo_request(1, sequence, payload.clone())?;
        socket.set_timeout(Some(Duration::from_secs(1)));
        let moment = socket
            .send_to(str_to_v4ip(&dest_ip)?, packet)
            .and_then(|_| Ok(Instant::now()))?;
        match socket.rcv_from() {
            Ok((packet, socket_addr)) => {
                let elapse = Instant::now() - moment;
                match packet.message {
                    Icmpv4Message::EchoReply {
                        identifier: _,
                        sequence,
                        payload,
                    } => {
                        let ip = *socket_addr.as_socket_ipv4().unwrap().ip();
                        println!(
                            "Ping {} icmp_seq={} time={}ms size={}",
                            ip,
                            sequence,
                            elapse.as_micros() as f64 / 1000.0,
                            payload.len()
                        );
                    }
                    Icmpv4Message::TimeExceeded {
                        padding: _,
                        header: _,
                    } => {
                        println!("icmp_seq={} timeout", sequence);
                    }
                    Icmpv4Message::Unreachable {
                        padding: _,
                        header: _,
                    } => {
                        println!("{dest_ip} is unreacheable");
                        break;
                    }
                    _ => {}
                }
            }
            Err(e) => {
                println!("Error: {}", e.to_string());
                break;
            }
        }
        if !infinite {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
        sequence = sequence.wrapping_add(1);
    }
    Ok(())
}
