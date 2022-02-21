use hbb_common::{
    bytes::BytesMut, new_listener, protobuf::Message as _, rendezvous_proto::*, tokio,
    udp::FramedSocket, AddrMangle, Stream,
};

use log;

//#[tokio::main(flavor = "current_thread")]
#[tokio::main]
async fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    let mut socket = FramedSocket::new_reuse("0.0.0.0:21115").await.unwrap();
    let mut listener = new_listener("0.0.0.0:21116", true).await.unwrap();
    //<self_id, (self_addr, pk)>
    let mut udp_map = std::collections::HashMap::<String, (std::net::SocketAddr, Vec<u8>)>::new();
    //<peer_id, (self_addr stream)>
    let mut tcp_map = std::collections::HashMap::<String, (std::net::SocketAddr, Stream)>::new();
    let relay_server = std::env::var("IP").unwrap();
    loop {
        tokio::select! {
            Some(Ok((bytes, addr))) = socket.next() => {
                log::debug!("new udp socket from addr:{:?}", addr);
                handle_udp(&mut socket, bytes, addr.into(), &mut udp_map).await;
            }
            Ok((stream, addr)) = listener.accept() => { //A tcp addr
                log::info!("tcp listener accept new from addr:{:?}", addr);
                let mut stream = Stream::from(stream, addr);
                if let Some(Ok(bytes)) = stream.next_timeout(3000).await {
                    if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                        match msg_in.union {
                            Some(rendezvous_message::Union::punch_hole_request(ph)) => {
                                log::info!("punch_hole_request {:?}, ph:{:?}", addr, ph);
                                if let Some((peer_addr, _pk)) = udp_map.get(&ph.id) { //B udp addr
                                    //给B发 udp punch request
                                    let mut msg_udp = RendezvousMessage::new();
                                    let send_ph = PunchHole {
                                        socket_addr: AddrMangle::encode(addr.clone()), // A tcp addr
                                         relay_server:relay_server.clone(),
                                         nat_type: ph.nat_type.clone(),
                                         ..Default::default()
                                        };
                                    msg_udp.set_punch_hole(send_ph.clone());
                                    let ret = socket.send(&msg_udp, peer_addr.clone()).await.ok();
                                    log::info!("send B {:?} PunchHole:{:?}, ret:{:?}", peer_addr, send_ph, ret);

                                    tcp_map.insert(ph.id, (addr.clone(), stream));
                                }
                            }
                            Some(rendezvous_message::Union::punch_hole_sent(phs)) => {
                                log::info!("recv punch_hole_sent {:?} from {:?}", phs, addr);
                                if let Some((_, stream)) = tcp_map.get_mut(&phs.id) {
                                    //给A回 tcp punch response
                                    if let Some((_, pk)) =  udp_map.get(&phs.id) {
                                        let mut msg_tcp = RendezvousMessage::new();
                                        let send_ph = PunchHoleResponse {
                                            socket_addr: AddrMangle::encode(addr.clone()), //B tcp addr
                                            pk: pk.clone(),
                                            relay_server:relay_server.clone(),
                                            ..Default::default()
                                        };
                                        msg_tcp.set_punch_hole_response(send_ph.clone());
                                        let ret = stream.send(&msg_tcp).await.ok();
                                        log::info!("send A {:?} PunchHoleResponse:{:?}, ret:{:?}", addr, send_ph, ret);
                                    }
                                } else {
                                    log::warn!("no registered {:?}", phs.id);
                                }

                            }
                            _ => {
                                log::warn!("other rz {:?}", msg_in);
                            }
                        }
                    } else {
                        log::warn!("tcp listener read stream is not rz message from addr:{:?}", addr);
                    }
                } else {
                    log::warn!("tcp listener read stream time out from addr:{:?}", addr);
                }
            }
        }
    }
}

async fn handle_udp(
    socket: &mut FramedSocket,
    bytes: BytesMut,
    addr: std::net::SocketAddr,
    id_map: &mut std::collections::HashMap<String, (std::net::SocketAddr, Vec<u8>)>,
) {
    if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
        log::debug!("udp rz bytes:{:?}", bytes);
        match msg_in.union {
            Some(rendezvous_message::Union::register_peer(rp)) => {
                log::debug!("register_peer addr:{:?}, rp:{:?}", addr, rp);
                let mut request_pk = true;
                if id_map.contains_key(&rp.id) {
                    let old = id_map.get(&rp.id).unwrap();
                    let mut old_cloned = old.clone();
                    old_cloned.0 = addr.clone();
                    if old_cloned.1.len() > 0 {
                        request_pk = false;
                    }
                    id_map.insert(rp.id.clone(), old_cloned);
                } else {
                    id_map.insert(rp.id.clone(), (addr, vec![]));
                }
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_register_peer_response(RegisterPeerResponse {
                    request_pk,
                    ..Default::default()
                });
                socket.send(&msg_out, addr).await.ok();
            }
            Some(rendezvous_message::Union::register_pk(pk)) => {
                log::info!("register_pk addr:{:?}, pk:{:?}", addr, pk);
                if id_map.contains_key(&pk.id) {
                    let old = id_map.get(&pk.id).unwrap();
                    let mut old_cloned = old.clone();
                    old_cloned.1 = pk.pk.clone();
                    id_map.insert(pk.id.clone(), old_cloned);
                } else {
                    id_map.insert(pk.id.clone(), (addr, vec![]));
                }
                log::info!("register pk: {:?}", id_map.get_key_value(&pk.id));
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_register_pk_response(RegisterPkResponse {
                    result: register_pk_response::Result::OK.into(),
                    ..Default::default()
                });
                socket.send(&msg_out, addr).await.ok();
            }
            _ => {
                log::warn!("udp receive other msg_in.union:{:?}", msg_in.union);
            }
        }
    } else {
        log::warn!("udp receive not RendezvousMessage:{:?}", bytes);
    }
}
