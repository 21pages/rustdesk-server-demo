use hbb_common::{
    bytes::BytesMut,
    protobuf::Message as _,
    rendezvous_proto::*,
    kcp::{new_listener, FramedStream},
    tokio,
    udp::FramedSocket,
    AddrMangle,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut socket = FramedSocket::new("0.0.0.0:21116").await.unwrap();
    let mut listener = new_listener("0.0.0.0:21118", false).await.unwrap();
    //保存
    //<self_id, (self_addr, pk)>
    let mut udp_map = std::collections::HashMap::<String, (std::net::SocketAddr, Vec<u8>)>::new();
    //<peer_id, (self_addr stream)>
    let mut tcp_map = std::collections::HashMap::<String, (std::net::SocketAddr, FramedStream)>::new();
    let relay_server = std::env::var("IP").unwrap();
    // let mut saved_stream_a : Option<FramedStream> = None;
    loop {
        tokio::select! {
            Some(Ok((bytes, addr))) = socket.next() => {
                println!("new udp socket from addr:{:?}", addr);
                handle_udp(&mut socket, bytes, addr.into(), &mut udp_map).await;
            }
            Ok((stream, addr)) = listener.accept() => { //A tcp addr
                println!("tcp listener accept new from addr:{:?}", addr);
                let mut stream = FramedStream::from(stream, addr);
                if let Some(Ok(bytes)) = stream.next_timeout(3000).await {
                    if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                        match msg_in.union {
                            Some(rendezvous_message::Union::punch_hole_request(ph)) => {
                                println!("punch_hole_request {:?}, ph:{:?}", addr, ph);
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
                                    println!("send B {:?} PunchHole:{:?}, ret:{:?}", peer_addr, send_ph, ret);

                                    // saved_stream_a = Some(stream);
                                    tcp_map.insert(ph.id, (addr.clone(), stream));
                                    //给A回 tcp punch response
                                    // let mut msg_tcp = RendezvousMessage::new();
                                    // let send_ph = PunchHoleResponse {
                                    //     socket_addr: AddrMangle::encode(peer_addr.clone()), //B udp addr
                                    //     pk: pk.clone(),
                                    //     relay_server:relay_server.clone(),
                                    //     ..Default::default()
                                    // };
                                    // msg_tcp.set_punch_hole_response(send_ph.clone());
                                    // let ret = stream.send(&msg_tcp).await.ok();
                                    // println!("send A {:?} PunchHoleResponse:{:?}, ret:{:?}", addr, send_ph, ret);

                                    //给A发 udp punch request
                                    // let mut msg_udp = RendezvousMessage::new();
                                    // let send_ph = PunchHole {
                                    //     socket_addr: AddrMangle::encode(addr.clone()), // A tcp addr
                                    //      relay_server:relay_server.clone(),
                                    //      nat_type: ph.nat_type.clone(),
                                    //      ..Default::default()
                                    //     };
                                    // msg_udp.set_punch_hole(send_ph.clone());
                                    // let ret = socket.send(&msg_udp, peer_addr.clone()).await.ok();
                                    // println!("send A {:?} PunchHole:{:?}, ret:{:?}", peer_addr, send_ph, ret);
                                }
                            }
                            Some(rendezvous_message::Union::punch_hole_sent(phs)) => {
                                println!("recv punch_hole_sent {:?} from {:?}", phs, addr);
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
                                            println!("send A {:?} PunchHoleResponse:{:?}, ret:{:?}", addr, send_ph, ret);
                                    }
                                } else {

                                }

                            }
                            _ => {
                                println!("other rz {:?}", msg_in);
                            }
                        }
                    } else {
                        println!("tcp listener read stream is not rz message from addr:{:?}", addr);
                    }
                } else {
                    println!("tcp listener read stream time out from addr:{:?}", addr);
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
        println!("udp rz bytes:{:?}", bytes);
        match msg_in.union {
            Some(rendezvous_message::Union::register_peer(rp)) => {
                println!("register_peer addr:{:?}, rp:{:?}", addr, rp);
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
                //println!("register peer: {:?}", id_map.get_key_value(&rp.id));
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_register_peer_response(RegisterPeerResponse {
                    request_pk,
                    ..Default::default()
                });
                socket.send(&msg_out, addr).await.ok();
            }
            Some(rendezvous_message::Union::register_pk(pk)) => {
                println!("register_pk addr:{:?}, pk:{:?}", addr, pk);
                if id_map.contains_key(&pk.id) {
                    let old = id_map.get(&pk.id).unwrap();
                    let mut old_cloned = old.clone();
                    old_cloned.1 = pk.pk.clone();
                    id_map.insert(pk.id.clone(), old_cloned);
                } else {
                    id_map.insert(pk.id.clone(), (addr, vec![]));
                }
                println!("register pk: {:?}", id_map.get_key_value(&pk.id));
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_register_pk_response(RegisterPkResponse {
                    result: register_pk_response::Result::OK.into(),
                    ..Default::default()
                });
                socket.send(&msg_out, addr).await.ok();
            }
            _ => {
                println!("udp receive other msg_in.union:{:?}", msg_in.union);
            }
        }
    } else {
        println!("udp receive not RendezvousMessage:{:?}", bytes);
    }
}
