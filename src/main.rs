use hbb_common::{
    bytes::BytesMut,
    protobuf::Message as _,
    rendezvous_proto::*,
    tcp::{new_listener, FramedStream},
    tokio,
    udp::FramedSocket,
};

/*
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
    let mut rlistener = new_listener("0.0.0.0:21117", false).await.unwrap();
    let mut id_map = std::collections::HashMap::new();
    let relay_server = std::env::var("IP").unwrap();
    let mut saved_stream = None;
    loop {
        tokio::select! {
            Some(Ok((bytes, addr))) = socket.next() => {
                println!("new udp socket from addr:{:?}", addr);
                handle_udp(&mut socket, bytes, addr, &mut id_map).await;
            }
            Ok((stream, addr)) = listener.accept() => {
                println!("tcp listener accept new from addr:{:?}", addr);
                let mut stream = FramedStream::from(stream);
                if let Some(Ok(bytes)) = stream.next_timeout(3000).await {
                    if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                        match msg_in.union {
                            Some(rendezvous_message::Union::punch_hole_request(ph)) => {
                                println!("punch_hole_request {:?}, ph:{:?}", addr, ph);
                                if let Some(addr) = id_map.get(&ph.id) { //根据id获取对方的addr
                                    let mut msg_out = RendezvousMessage::new();
                                    msg_out.set_request_relay(RequestRelay {
                                        relay_server: relay_server.clone(),
                                        ..Default::default()
                                    });
                                    socket.send(&msg_out, addr.clone()).await.ok(); //发送给对方地址
                                    saved_stream = Some(stream); //保留请求方的tcp socket
                                }
                            }
                            Some(rendezvous_message::Union::relay_response(_)) => {
                                println!("relay_response {:?}", addr); //收到被请求方的回复
                                let mut msg_out = RendezvousMessage::new();
                                msg_out.set_relay_response(RelayResponse {
                                    relay_server: relay_server.clone(),
                                    ..Default::default()
                                });
                                if let Some(mut stream) = saved_stream.take() { //获取之前请求方的tcp socket
                                    stream.send(&msg_out).await.ok(); //给请求方发送一个relay response, 带着服务器地址
                                    if let Ok((stream_a, _)) = rlistener.accept().await {
                                        let mut stream_a = FramedStream::from(stream_a);
                                        stream_a.next_timeout(3_000).await; //读取一个连接的一包数据
                                        if let Ok((stream_b, _)) = rlistener.accept().await {
                                            let mut stream_b = FramedStream::from(stream_b);
                                            stream_b.next_timeout(3_000).await; //读取一个另一个连接的一包数据
                                            relay(stream_a, stream_b, &mut socket, &mut id_map).await;
                                        }
                                    }
                                }
                            }
                            _ => {}
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

async fn relay(
    stream: FramedStream,
    peer: FramedStream,
    socket: &mut FramedSocket,
    id_map: &mut std::collections::HashMap<String, std::net::SocketAddr>,
) {
    let mut peer = peer;
    let mut stream = stream;
    peer.set_raw();
    stream.set_raw();
    loop {
        tokio::select! {
            //处理定时的udp注册请求
            Some(Ok((bytes, addr))) = socket.next() => {
                println!("relay udp receive from addr:{:?}", addr);
                handle_udp(socket, bytes, addr, id_map).await;
            }
            //两个连接互相转发数据
            res = peer.next() => {
                println!("relay peer receive");
                if let Some(Ok(bytes)) = res {
                    stream.send_bytes(bytes.into()).await.ok();
                } else {
                    break;
                }
            },
            res = stream.next() => {
                println!("relay stream receive");
                if let Some(Ok(bytes)) = res {
                    peer.send_bytes(bytes.into()).await.ok();
                } else {
                    break;
                }
            },
        }
    }
}

async fn handle_udp(
    socket: &mut FramedSocket,
    bytes: BytesMut,
    addr: std::net::SocketAddr,
    id_map: &mut std::collections::HashMap<String, std::net::SocketAddr>,
) {
    if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
        println!("udp rz bytes:{:?}", bytes);
        match msg_in.union {
            Some(rendezvous_message::Union::register_peer(rp)) => {
                println!("register_peer addr:{:?}, rp:{:?}", addr, rp);
                id_map.insert(rp.id, addr);
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_register_peer_response(RegisterPeerResponse::new());
                socket.send(&msg_out, addr).await.ok();
            }
            Some(rendezvous_message::Union::register_pk(pk)) => {
                println!("register_pk addr:{:?}, pk:{:?}", addr, pk);
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

/*
new udp socket from addr:192.168.1.11:51830
register_peer addr:192.168.1.11:51830, rp:id: "335976854" serial: 1
new udp socket from addr:192.168.1.6:64613
register_peer addr:192.168.1.6:64613, rp:id: "362587269" serial: 1
new udp socket from addr:192.168.1.6:60845
new udp socket from addr:192.168.1.11:51830
register_peer addr:192.168.1.11:51830, rp:id: "335976854" serial: 1
new udp socket from addr:192.168.1.6:64613
register_peer addr:192.168.1.6:64613, rp:id: "362587269" serial: 1
new udp socket from addr:192.168.1.11:53118
tcp listener accept new from addr:192.168.1.6:2885
punch_hole_request 192.168.1.6:2885
tcp listener accept new from addr:192.168.1.11:51041
relay_response 192.168.1.11:51041
relay stream receive
relay peer receive
relay stream receive
relay peer receive
...
relay stream receive
relay stream receive
relay udp receive from addr:192.168.1.11:51830
register_peer addr:192.168.1.11:51830, rp:id: "335976854" serial: 1
relay peer receive
relay stream receive
relay stream receive
relay stream receive
relay stream receive
relay udp receive from addr:192.168.1.6:64613
register_peer addr:192.168.1.6:64613, rp:id: "362587269" serial: 1
relay stream receive
relay peer receive
relay stream receive
relay stream receive
...
*/
