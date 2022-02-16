use hbb_common::{
    bytes::BytesMut,
    protobuf::Message as _,
    rendezvous_proto::*,
    tcp::{new_listener, FramedStream},
    tokio,
    udp::FramedSocket,
    AddrMangle,
};

/*
打洞思想
1. udp: 两个分别注册自己的socketaddr, id
    rendezvous_mediator.rs start()
        timer.tick()
            allow_err!(rz.register_peer(&mut socket).await);
2. 点击'连接', tcp连过来,ip不变端口变, punch request, 带着对方的id和自己的nat类型
    client.rs _start()
        let rendezvous_server = crate::get_rendezvous_server(1_000).await;
        set_punch_hole_request && send to rendezvous_server
            收到服务器发送的PunchHoleResponse,带着被连接方的公网ip
            同时向被请求方发送udp信息, 里面带着请求方的公网ip


原中继转发思想
1. udp: 两个分别注册自己的socketaddr, id
    rendezvous_mediator.rs start()
        timer.tick()
            allow_err!(rz.register_peer(&mut socket).await);
2. 点击'连接', 第一个tcp连过来,ip不变端口变, punch request, 带着对方的id和自己的nat类型
    client.rs _start()
        let rendezvous_server = crate::get_rendezvous_server(1_000).await;
        set_punch_hole_request && send to rendezvous_server
            收到服务器发送的relay_response,里面带着第二个tcp的ip(port)
                create_relay, 连接这个ip, 并发送消息

3. 用udp给被请求方地址发RequestRelay, 带着服务器的地址信息, 保留请求的tcpsocket
4. 被请求方收到RequestRelay, 返回relay_response, 然后给请求方发送RelayResponse, 带着服务器地址
    rendezvous_mediator.rs start() select!
        收到request_relay,handle_request_relay, 连接到第一个tcp端口发送, 一个relay_response
            create_relay_connection


5. 用relay服务器的地址, 接受两个连接, 这两个连接间互相转发数据,此时,udp用于处理定时的注册服务

*/

#[tokio::main(basic_scheduler)]
async fn main() {
    let mut socket = FramedSocket::new("0.0.0.0:21116").await.unwrap();
    let mut listener = new_listener("0.0.0.0:21116", false).await.unwrap();
    //保存
    let mut id_map = std::collections::HashMap::<String, (std::net::SocketAddr, Vec<u8>)>::new();
    let relay_server = std::env::var("IP").unwrap();
    loop {
        tokio::select! {
            Some(Ok((bytes, addr))) = socket.next() => {
                println!("new udp socket from addr:{:?}", addr);
                handle_udp(&mut socket, bytes, addr, &mut id_map).await;
            }
            Ok((stream, addr)) = listener.accept() => { //A tcp addr
                println!("tcp listener accept new from addr:{:?}", addr);
                let mut stream = FramedStream::from(stream);
                if let Some(Ok(bytes)) = stream.next_timeout(3000).await {
                    if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                        match msg_in.union {
                            Some(rendezvous_message::Union::punch_hole_request(ph)) => {
                                println!("punch_hole_request {:?}, ph:{:?}", addr, ph);
                                if let Some((peer_addr, pk)) = id_map.get(&ph.id) { //B udp addr
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
