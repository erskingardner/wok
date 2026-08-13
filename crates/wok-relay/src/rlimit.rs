//! Process resource limits, mirroring C++ `onAppStartup.cpp` `setRLimits`.

/// Apply `relay.nofiles` (0 = don't attempt). On macOS/FreeBSD the requested
/// value is clamped to the hard limit like C++; on Linux exceeding the hard
/// limit is an error.
pub fn apply_nofiles_limit(nofiles: u64) -> Result<(), String> {
    if nofiles == 0 {
        return Ok(());
    }
    let mut curr = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut curr) } != 0 {
        return Err(format!(
            "couldn't call getrlimit: {}",
            std::io::Error::last_os_error()
        ));
    }
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        tracing::info!(
            "getrlimit NOFILES limit current {} with max of {}",
            curr.rlim_cur,
            curr.rlim_max
        );
        if nofiles > curr.rlim_max {
            tracing::info!(
                "Unable to set NOFILES limit to {nofiles}, exceeds max of {}",
                curr.rlim_max
            );
            if curr.rlim_cur < curr.rlim_max {
                tracing::info!("Setting NOFILES limit to max of {}", curr.rlim_max);
                curr.rlim_cur = curr.rlim_max;
            }
        } else {
            curr.rlim_cur = nofiles;
        }
        tracing::info!("setrlimit NOFILES limit to {}", curr.rlim_cur);
    }
    #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
    {
        if nofiles > curr.rlim_max {
            return Err(format!(
                "Unable to set NOFILES limit to {nofiles}, exceeds max of {}",
                curr.rlim_max
            ));
        }
        curr.rlim_cur = nofiles;
    }
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &curr) } != 0 {
        return Err(format!(
            "Failed setting NOFILES limit to {}: {}",
            curr.rlim_cur,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn zero_is_noop() {
        super::apply_nofiles_limit(0).unwrap();
    }

    #[test]
    fn current_limit_roundtrips() {
        // Setting the limit to its current value is always permitted.
        let mut curr = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut curr) },
            0
        );
        super::apply_nofiles_limit(curr.rlim_cur).unwrap();
    }
}
