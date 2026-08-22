#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use fips::native::client::FipsAddr;
    use std::path::Path;

    let mut args = std::env::args().skip(1);
    let socket = args
        .next()
        .ok_or("usage: native-client SOCKET NPUB:PORT MESSAGE")?;
    let destination: FipsAddr = args
        .next()
        .ok_or("usage: native-client SOCKET NPUB:PORT MESSAGE")?
        .parse()?;
    let message = args
        .next()
        .ok_or("usage: native-client SOCKET NPUB:PORT MESSAGE")?;
    if args.next().is_some() {
        return Err("usage: native-client SOCKET NPUB:PORT MESSAGE".into());
    }

    let exchange = support::client::exchange(Path::new(&socket), destination, &message, |reply| {
        reply.contains("\"EOSE\"") || reply.contains("\"OK\"")
    })?;
    let _max_datagram = exchange.max_datagram;
    for reply in exchange.responses {
        println!("{reply}");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
mod support;

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
fn main() {
    eprintln!("the native FIPS client is supported only on Linux, FreeBSD, and macOS");
    std::process::exit(2);
}
