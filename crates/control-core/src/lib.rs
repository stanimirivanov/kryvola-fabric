//! Foundation control boundaries. This crate implements no encryption or inference.
#[path = "../../../contracts/spec/rust/artifact_ref.rs"]
pub mod contract;
#[path = "../../../contracts/spec/rust/limits.rs"]
pub mod limits;

#[derive(Debug, PartialEq, Eq)]
pub struct ControlTooLarge {
    pub actual: usize,
    pub maximum: usize,
}

/// Enforce byte budgets before transport; this does not validate message contents.
pub fn check_control_size(actual: usize, temporal: bool) -> Result<(), ControlTooLarge> {
    let maximum = if temporal {
        limits::TEMPORAL_PAYLOAD_BYTES
    } else {
        limits::CONTROL_BYTES
    };
    if actual > maximum {
        Err(ControlTooLarge { actual, maximum })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_transport_boundaries_reject_oversized_payloads() {
        for temporal in [false, true] {
            let limit = if temporal {
                limits::TEMPORAL_PAYLOAD_BYTES
            } else {
                limits::CONTROL_BYTES
            };
            assert_eq!(check_control_size(limit, temporal), Ok(()));
            assert_eq!(
                check_control_size(limit + 1, temporal),
                Err(ControlTooLarge {
                    actual: limit + 1,
                    maximum: limit
                })
            );
            assert!(check_control_size(usize::MAX, temporal).is_err());
        }
    }
}
