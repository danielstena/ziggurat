use super::*;
use crate::runtime::TokioSpawner;
use crate::zigbee_stack::{DeliveryError, NetworkConfig, Tunables, WELL_KNOWN_LINK_KEY};
use abstract_bits::{AbstractBits, BitReader};
use alloc::sync::Arc;
use ziggurat_ieee_802154::Ieee802154DataFrame;
use ziggurat_phy::{ExclusiveRadio, RadioConfig, RadioError, Receiver, TxFrame, TxResult};
use ziggurat_zigbee::nwk::frame::{NwkAuxHeader, NwkSecurityHeaderControlField};

#[derive(Debug)]
struct NoRadio;

struct EmptyReceiver;
impl<T: Send> Receiver<T> for EmptyReceiver {
    async fn recv(&mut self) -> Option<T> {
        None
    }
}
impl ExclusiveRadio for &NoRadio {
    async fn set_channel(&self, _: u8) -> Result<(), RadioError> {
        Ok(())
    }
    async fn transmit(&self, _: TxFrame) -> Result<TxResult, RadioError> {
        Ok(TxResult::Acked)
    }
}
impl RadioPhy for NoRadio {
    type Exclusive<'a> = &'a Self;
    type RxStream = EmptyReceiver;
    type ResetStream = EmptyReceiver;
    async fn reset(&self) -> Result<(), RadioError> {
        Ok(())
    }
    async fn reconfigure(&self, _: &RadioConfig) -> Result<(), RadioError> {
        Ok(())
    }
    async fn set_frame_pending_table(&self, _: &[Nwk], _: &[Eui64]) -> Result<(), RadioError> {
        Ok(())
    }
    async fn transmit(&self, _: TxFrame) -> Result<TxResult, RadioError> {
        Ok(TxResult::Acked)
    }
    async fn energy_detect(&self, _: u8, _: Duration) -> Result<i8, RadioError> {
        Ok(-80)
    }
    async fn lock(&self) -> Self::Exclusive<'_> {
        self
    }
    fn subscribe_rx(&self) -> Self::RxStream {
        EmptyReceiver
    }
    fn subscribe_reset(&self) -> Self::ResetStream {
        EmptyReceiver
    }
}

fn peer() -> Eui64 {
    Eui64::from_hex("00124b0000000001")
}
fn other() -> Eui64 {
    Eui64::from_hex("00124b0000000002")
}
fn stack() -> Arc<ZigbeeStack<NoRadio>> {
    ZigbeeStack::new(
        Arc::new(NoRadio),
        NetworkConfig {
            role: NwkDeviceType::Coordinator,
            channel: 15,
            update_id: 0,
            pan_id: ziggurat_ieee_802154::types::PanId(0x1234),
            extended_pan_id: Eui64::from_hex("00124b0000000000"),
            network_address: Nwk(0),
            ieee_address: Eui64::from_hex("00124b0000000000"),
            network_key: Key::from_hex("00112233445566778899aabbccddeeff"),
            network_key_seq_number: 0,
            network_key_tx_counter: 500,
            tc_link_key: WELL_KNOWN_LINK_KEY,
            tclk_seed: None,
            tx_power: 0,
            source_routing: false,
        },
        Tunables::default(),
        TokioSpawner::default(),
    )
}

fn receive_leave(
    stack: &ZigbeeStack<NoRadio>,
    rejoin: bool,
    request: bool,
    relayer: Eui64,
    valid_mic: bool,
) -> bool {
    receive_secured_command(
        stack,
        NwkCommand::Leave(NwkLeaveCommand {
            request,
            rejoin,
            remove_children: false,
        }),
        relayer,
        58,
        valid_mic,
    )
}

fn receive_secured_command(
    stack: &ZigbeeStack<NoRadio>,
    command: NwkCommand,
    relayer: Eui64,
    counter: u32,
    valid_mic: bool,
) -> bool {
    receive_secured_command_from(stack, command, relayer, counter, valid_mic, Nwk(0x4831))
}

fn receive_secured_command_from(
    stack: &ZigbeeStack<NoRadio>,
    command: NwkCommand,
    relayer: Eui64,
    counter: u32,
    valid_mic: bool,
    mac_sender: Nwk,
) -> bool {
    let mut frame = stack.nwk_command_frame(Nwk(0), command);
    frame.nwk_header.source = Nwk(0x4831);
    frame.nwk_header.source_ieee = Some(peer());
    frame.aux_header = Some(NwkAuxHeader {
        security_control: NwkSecurityHeaderControlField::read_abstract_bits(&mut BitReader::from(
            &[0x28][..],
        ))
        .unwrap(),
        frame_counter: counter,
        extended_source: Some(relayer),
        key_sequence_number: 0,
    });
    let key = stack.core().nib.nwk_security.network_key();
    let mut bytes = frame.encrypt(&key).to_bytes();
    if !valid_mic {
        *bytes.last_mut().unwrap() ^= 1;
    }
    let mut header = stack
        .build_802154_association_response::<FrameBytes>(
            peer(),
            Nwk(0x4831),
            Ieee802154AssociationStatus::AssociationSuccessful,
        )
        .header()
        .clone();
    header.frame_control.frame_type = Ieee802154FrameType::Data;
    header.frame_control.src_addr_mode = Ieee802154AddressingMode::Short;
    header.frame_control.dest_addr_mode = Ieee802154AddressingMode::Short;
    header.src_address = Some(Ieee802154Address::Nwk(mac_sender));
    header.dest_address = Some(Ieee802154Address::Nwk(Nwk(0)));
    stack
        .process_802154_data_frame(
            &Ieee802154DataFrame {
                header,
                payload: FrameBytes::from_slice(&bytes).unwrap(),
                fcs: 0,
            },
            100,
            -50,
        )
        .is_some()
}

fn associate(stack: &ZigbeeStack<NoRadio>) {
    let request =
        Ieee802154AssociationRequestCommand::read_abstract_bits(&mut BitReader::from(&[0x80][..]))
            .unwrap();
    let mut header = stack
        .build_802154_association_response::<FrameBytes>(
            peer(),
            Nwk(0x4831),
            Ieee802154AssociationStatus::AssociationSuccessful,
        )
        .header()
        .clone();
    header.src_address = Some(Ieee802154Address::Eui64(peer()));
    header.dest_address = Some(Ieee802154Address::Eui64(stack.state.ieee_address));
    stack.process_802154_association_request(
        &Ieee802154CommandFrame {
            header,
            command_payload: Ieee802154CommandPayload::AssociationRequest(request.clone()),
            fcs: 0,
        },
        &request,
    );
}

async fn extract(stack: &ZigbeeStack<NoRadio>, result: Result<(), DeliveryError>) {
    for _ in 0..100 {
        let nwk = stack.core().nib.address_map.nwk_for(peer());
        let delivery = stack
            .core()
            .mac
            .indirect_queue
            .extract(Some(peer()), nwk, stack.core_now())
            .delivery;
        if let Some(delivery) = delivery {
            stack.resolve_outcome(delivery.transaction.completion, result);
            tokio::task::yield_now().await;
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("join did not queue its expected indirect frame");
}

fn replay_rejected(stack: &ZigbeeStack<NoRadio>, sender: Eui64, counter: u32) -> bool {
    stack
        .core()
        .nib
        .nwk_security
        .inbound_network_key(sender, 0, counter)
        .is_none()
}

async fn complete_association(stack: &Arc<ZigbeeStack<NoRadio>>) {
    associate(stack);
    extract(stack, Ok(())).await; // MAC association response
    extract(stack, Ok(())).await; // network key
}

#[tokio::test]
async fn authenticated_departure_and_fresh_key_delivery_admit_reset_counter_once() {
    let stack = stack();
    stack
        .core()
        .nib
        .nwk_security
        .note_inbound_frame_counter(peer(), 57);
    stack
        .core()
        .nib
        .nwk_security
        .note_inbound_frame_counter(other(), 900);
    assert!(receive_leave(&stack, false, false, peer(), true));
    assert!(replay_rejected(&stack, peer(), 0)); // leave alone cannot admit a replay
    stack.permit_joins(180, true);
    let running = stack.clone();
    let runner = tokio::spawn(async move { running.tasklet_task().await });
    associate(&stack);
    extract(&stack, Ok(())).await;
    assert!(replay_rejected(&stack, peer(), 0)); // association response alone is insufficient
    extract(&stack, Ok(())).await;
    assert!(
        !replay_rejected(&stack, peer(), 0),
        "reset sensor must be able to answer Active_EP"
    );
    // Exercise the encrypted MAC -> NWK receive path, not just a table lookup.
    let command = NwkCommand::Unparsed(FrameBytes::from_slice(&[0xfe]).unwrap());
    assert!(receive_secured_command(
        &stack,
        command.clone(),
        peer(),
        0,
        true
    ));
    assert!(!receive_secured_command(&stack, command, peer(), 0, true));
    assert!(replay_rejected(&stack, other(), 900));
    stack
        .core()
        .nib
        .nwk_security
        .note_inbound_frame_counter(peer(), 6);
    complete_association(&stack).await; // duplicate association/key extraction
    assert!(replay_rejected(&stack, peer(), 6));
    assert!(!replay_rejected(&stack, peer(), 7));
    runner.abort();
}

#[tokio::test]
async fn failed_key_delivery_keeps_replay_floor_until_a_successful_retry() {
    let stack = stack();
    stack
        .core()
        .nib
        .nwk_security
        .note_inbound_frame_counter(peer(), 57);
    assert!(receive_leave(&stack, false, false, peer(), true));
    stack.permit_joins(180, true);
    let running = stack.clone();
    let runner = tokio::spawn(async move { running.tasklet_task().await });
    associate(&stack);
    extract(&stack, Ok(())).await;
    extract(&stack, Err(DeliveryError::Cancelled)).await;
    assert!(replay_rejected(&stack, peer(), 0));
    complete_association(&stack).await;
    assert!(!replay_rejected(&stack, peer(), 0));
    runner.abort();
}

#[tokio::test]
async fn rejoin_requested_leave_and_invalid_or_relayed_leave_keep_replay_floor() {
    for (rejoin, request, relayer, valid_mic) in [
        (true, false, peer(), true),
        (false, true, peer(), true),
        (false, false, other(), true),
        (false, false, peer(), false),
    ] {
        let stack = stack();
        stack
            .core()
            .nib
            .nwk_security
            .note_inbound_frame_counter(peer(), 57);
        assert_eq!(
            receive_leave(&stack, rejoin, request, relayer, valid_mic),
            valid_mic
        );
        stack.permit_joins(180, true);
        let running = stack.clone();
        let runner = tokio::spawn(async move { running.tasklet_task().await });
        complete_association(&stack).await;
        assert!(replay_rejected(&stack, peer(), 0));
        runner.abort();
    }
}

#[tokio::test]
async fn closed_admission_and_ordinary_association_keep_replay_floor() {
    let stack = stack();
    stack
        .core()
        .nib
        .nwk_security
        .note_inbound_frame_counter(peer(), 57);
    assert!(receive_leave(&stack, false, false, peer(), true));
    associate(&stack); // denied: no permit-join window
    assert!(replay_rejected(&stack, peer(), 0));
    assert!(stack.core().nib.address_map.nwk_for(peer()).is_some()); // leave retained old mapping
    let ordinary = self::stack();
    ordinary
        .core()
        .nib
        .nwk_security
        .note_inbound_frame_counter(peer(), 57);
    ordinary.permit_joins(180, true);
    let running = ordinary.clone();
    let runner = tokio::spawn(async move { running.tasklet_task().await });
    complete_association(&ordinary).await;
    assert!(replay_rejected(&ordinary, peer(), 0));
    runner.abort();
}

#[tokio::test]
async fn relayed_mac_sender_cannot_retire_the_originators_replay_floor() {
    let stack = stack();
    stack
        .core()
        .nib
        .nwk_security
        .note_inbound_frame_counter(peer(), 57);
    assert!(receive_secured_command_from(
        &stack,
        NwkCommand::Leave(NwkLeaveCommand {
            request: false,
            rejoin: false,
            remove_children: false,
        }),
        peer(),
        58,
        true,
        Nwk(0x9902),
    ));
    stack.permit_joins(180, true);
    let running = stack.clone();
    let runner = tokio::spawn(async move { running.tasklet_task().await });
    complete_association(&stack).await;
    assert!(replay_rejected(&stack, peer(), 0));
    runner.abort();
}
