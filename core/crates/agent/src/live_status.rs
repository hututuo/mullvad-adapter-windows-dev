//! Presentation of physical evidence; never changes recovery ownership or paths.
use adapter_domain::Attachment;

pub(crate) fn attachment_status(
    attachment: Attachment,
    paused: bool,
    previous: &str,
    has_path: bool,
    binding_changed: bool,
) -> Option<&'static str> {
    // Network evidence must not hide an explicit stop or a failed front.
    if matches!(previous, "disconnecting" | "blocked" | "starting_front")
        || (!has_path && previous == "disconnected")
    {
        return None;
    }
    if paused {
        Some("waiting_network")
    } else if attachment == Attachment::Unknown && has_path {
        Some("unknown_network")
    } else if matches!(previous, "waiting_network" | "unknown_network")
        || (binding_changed && has_path)
    {
        Some(if has_path {
            "network_recovering"
        } else {
            "disconnected"
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_path_outage_and_settling_never_project_as_manual_disconnect() {
        let mut status = "connected";
        for (attachment, paused, expected) in [
            (Attachment::Unknown, false, "unknown_network"),
            (Attachment::Unavailable, true, "waiting_network"),
            (Attachment::Unknown, true, "waiting_network"),
            (Attachment::Available, true, "waiting_network"),
            (Attachment::Available, false, "network_recovering"),
        ] {
            status = attachment_status(attachment, paused, status, true, false).unwrap();
            assert_eq!(status, expected);
        }
        // Only a fresh connection result changes this to connected.
        assert_eq!(
            attachment_status(Attachment::Available, false, status, true, false),
            None
        );
    }

    #[test]
    fn a_different_available_binding_requires_fresh_path_verification() {
        assert_eq!(
            attachment_status(Attachment::Available, false, "connected", true, true),
            Some("network_recovering")
        );
        assert_eq!(
            attachment_status(Attachment::Available, false, "connected", true, false),
            None
        );
    }

    #[test]
    fn no_saved_path_does_not_invent_a_reconnect_or_unknown_outage() {
        assert_eq!(
            attachment_status(Attachment::Unknown, false, "disconnected", false, false),
            None
        );
        assert_eq!(
            attachment_status(
                Attachment::Available,
                false,
                "waiting_network",
                false,
                false
            ),
            Some("disconnected")
        );
        assert_eq!(
            attachment_status(Attachment::Available, false, "disconnecting", false, false),
            None
        );
        for status in ["disconnecting", "blocked", "starting_front"] {
            assert_eq!(
                attachment_status(Attachment::Unavailable, true, status, true, true),
                None
            );
            assert_eq!(
                attachment_status(Attachment::Unknown, false, status, true, true),
                None
            );
        }
        assert_eq!(
            attachment_status(Attachment::Unavailable, true, "disconnected", false, true),
            None
        );
    }
}
