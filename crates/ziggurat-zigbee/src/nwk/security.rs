use crate::flat_map::FlatMap;

use ziggurat_ieee_802154::types::{Eui64, Key};

#[derive(Debug)]
enum NetworkKeyType {
    Standard = 1,
}

#[derive(Debug)]
struct NwkSecurityDescriptor {
    key_seq_number: u8,
    outgoing_frame_counter: u32,
    incoming_frame_counter_set: FlatMap<Eui64, u32>,
    key: Key,
    #[allow(dead_code)]
    network_key_type: NetworkKeyType,
}

/// The outcome of advancing the outgoing NWK security frame counter.
#[derive(Debug)]
#[must_use = "the advanced counter must be written into the frame and persisted when \
    requested; dropping it risks reusing a counter or a rollback on restart"]
pub struct CounterAdvance {
    pub value: u32,
    /// The client's persisted copy of the counter should be refreshed: a rollback
    /// after a restart would make every device silently reject our frames
    pub should_persist: bool,
}

/// One completed, authenticated departure awaiting a new association. Captured
/// at admission so an older join task cannot reset a later security epoch.
#[derive(Debug, Clone, Copy)]
pub struct NewJoinCounterReset {
    sender: Eui64,
    generation: u64,
}

/// The NWK security material: the network key, its outgoing frame counter, and the
/// per-relayer incoming frame counters used for replay protection (spec 4.3.1.2).
#[derive(Debug)]
pub struct NwkSecurity {
    primary: NwkSecurityDescriptor,
    /// Key rotation is not yet implemented; the alternate material is a placeholder
    #[allow(dead_code)]
    alternate: NwkSecurityDescriptor,
    active_key_seq_number: u8,
    /// Indicates whether incoming NWK frames SHALL be all checked for freshness when
    /// the memory for incoming frame counts is exceeded.
    #[allow(dead_code)]
    all_fresh: bool,
    /// Every this many outgoing frames, a counter advance asks to be persisted
    persist_interval: u32,
    departed: FlatMap<Eui64, u64>,
    departure_generation: u64,
}

impl NwkSecurity {
    pub fn new(
        key: Key,
        key_seq_number: u8,
        outgoing_frame_counter: u32,
        persist_interval: u32,
    ) -> Self {
        Self {
            primary: NwkSecurityDescriptor {
                key_seq_number,
                outgoing_frame_counter,
                incoming_frame_counter_set: FlatMap::new(),
                key,
                network_key_type: NetworkKeyType::Standard,
            },
            alternate: NwkSecurityDescriptor {
                key_seq_number: 0,
                outgoing_frame_counter: 0,
                incoming_frame_counter_set: FlatMap::new(),
                key: Key::from_hex("00000000000000000000000000000000"),
                network_key_type: NetworkKeyType::Standard,
            },
            active_key_seq_number: key_seq_number,
            all_fresh: false,
            persist_interval,
            departed: FlatMap::new(),
            departure_generation: 0,
        }
    }

    pub fn network_key(&self) -> Key {
        self.primary.key.clone()
    }

    pub const fn key_seq_number(&self) -> u8 {
        self.primary.key_seq_number
    }

    pub const fn active_key_seq_number(&self) -> u8 {
        self.active_key_seq_number
    }

    pub const fn outgoing_frame_counter(&self) -> u32 {
        self.primary.outgoing_frame_counter
    }

    /// Advance the outgoing security frame counter. The counter must never wrap:
    /// that would reuse a CCM* nonce. The spec's remedy near the end of the counter
    /// space is key rotation, which is not yet implemented.
    pub const fn next_outgoing_frame_counter(&mut self) -> CounterAdvance {
        self.primary.outgoing_frame_counter =
            self.primary.outgoing_frame_counter.checked_add(1).unwrap();

        let value = self.primary.outgoing_frame_counter;

        CounterAdvance {
            value,
            should_persist: value.is_multiple_of(self.persist_interval),
        }
    }

    /// Validate an inbound secured frame's auxiliary header against the active
    /// security material, returning the key to decrypt it with. `None` rejects the
    /// frame: an unknown key sequence number, or a frame counter that rolled
    /// backward for the relaying device (replay protection, spec 4.3.1.2).
    pub fn inbound_network_key(
        &self,
        sender: Eui64,
        key_sequence_number: u8,
        frame_counter: u32,
    ) -> Option<Key> {
        if key_sequence_number != self.active_key_seq_number {
            tracing::debug!("Ignoring frame, key sequence number is unknown");
            return None;
        }

        // Spec 4.3.1.2 step 1: a frame counter at its maximum value is rejected
        // outright; the sender must rotate the network key before it wraps.
        if frame_counter == u32::MAX {
            tracing::warn!(
                ?sender,
                frame_counter,
                "Rejecting NWK frame because its security counter is exhausted"
            );
            return None;
        }

        match self.primary.incoming_frame_counter_set.get(&sender) {
            None => {
                tracing::debug!("Unknown sender, not validating frame counter");
            }
            Some(&last_stored_frame_counter) => {
                if frame_counter <= last_stored_frame_counter {
                    tracing::warn!(
                        ?sender,
                        frame_counter,
                        last_stored_frame_counter,
                        "Rejecting replayed NWK frame counter"
                    );
                    return None;
                }
            }
        }

        Some(self.primary.key.clone())
    }

    /// Store the security frame counter of a successfully decrypted frame for its
    /// relaying device, the baseline for future replay checks.
    pub fn note_inbound_frame_counter(&mut self, sender: Eui64, frame_counter: u32) -> Option<u32> {
        self.primary
            .incoming_frame_counter_set
            .insert(sender, frame_counter)
    }

    /// Called only for a successfully authenticated, direct leave announcement
    /// with rejoin=false. Keep the old replay floor until a newly admitted device
    /// actually extracts its network key; departure alone does not admit traffic.
    pub fn note_authenticated_departure(&mut self, sender: Eui64) {
        self.departure_generation = self.departure_generation.checked_add(1).unwrap();
        self.departed.insert(sender, self.departure_generation);
    }

    pub fn new_join_counter_reset(&self, sender: Eui64) -> Option<NewJoinCounterReset> {
        self.departed
            .get(&sender)
            .map(|&generation| NewJoinCounterReset { sender, generation })
    }

    /// Complete the peer's fresh association exactly once. Ordinary rejoins,
    /// duplicate associations and stale completions keep their replay floor.
    pub fn complete_new_join(&mut self, reset: NewJoinCounterReset) -> bool {
        if self.departed.get(&reset.sender) != Some(&reset.generation) {
            return false;
        }
        self.departed.remove(&reset.sender);
        self.primary
            .incoming_frame_counter_set
            .remove(&reset.sender);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn security() -> NwkSecurity {
        NwkSecurity::new(
            Key::from_hex("00112233445566778899aabbccddeeff"),
            3,
            500,
            100,
        )
    }

    #[test]
    fn stale_join_completion_cannot_consume_a_later_departure() {
        let sender = Eui64::from_hex("00124b0000000001");
        let mut security = security();
        security.note_inbound_frame_counter(sender, 58);
        security.note_authenticated_departure(sender);
        let old = security.new_join_counter_reset(sender).unwrap();
        security.note_authenticated_departure(sender);
        assert!(!security.complete_new_join(old));
        assert!(security.inbound_network_key(sender, 3, 0).is_none());
        let current = security.new_join_counter_reset(sender).unwrap();
        assert!(security.complete_new_join(current));
        security.note_inbound_frame_counter(sender, 6);
        assert!(!security.complete_new_join(current));
        assert!(security.inbound_network_key(sender, 3, 6).is_none());
    }

    #[test]
    fn fresh_counter_epoch_preserves_key_sequence_exhaustion_and_outgoing_counter() {
        let sender = Eui64::from_hex("00124b0000000001");
        let mut security = security();
        assert!(security.new_join_counter_reset(sender).is_none());
        security.note_inbound_frame_counter(sender, 58);
        security.note_authenticated_departure(sender);
        let reset = security.new_join_counter_reset(sender).unwrap();
        assert!(security.complete_new_join(reset));
        assert!(security.inbound_network_key(sender, 3, 0).is_some());
        assert!(security.inbound_network_key(sender, 2, 0).is_none());
        assert!(security.inbound_network_key(sender, 3, u32::MAX).is_none());
        assert_eq!(security.next_outgoing_frame_counter().value, 501);
    }
}
