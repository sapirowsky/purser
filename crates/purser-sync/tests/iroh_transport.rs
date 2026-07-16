use purser_sync::{
    accept_pairing, bind_pairing, connect_pairing, request_pairing, serve_pairing, IrohTransport,
    PairingCode, PairingKeyMaterial, Record, Transport,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[test]
fn two_real_iroh_endpoints_round_trip_an_opaque_record() {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(30), async {
                let server_endpoint = IrohTransport::bind(iroh::SecretKey::generate())
                    .await
                    .unwrap();
                let port = server_endpoint
                    .bound_sockets()
                    .into_iter()
                    .find(SocketAddr::is_ipv4)
                    .unwrap()
                    .port();
                let server_addr = iroh::EndpointAddr::new(server_endpoint.id())
                    .with_ip_addr(SocketAddr::from(([127, 0, 0, 1], port)));
                let accepting_endpoint = server_endpoint.clone();
                let server = tokio::spawn(async move {
                    let (transport, _) = IrohTransport::accept(&accepting_endpoint).await.unwrap();
                    let record = transport.recv().await.unwrap();
                    transport.send(&record).await.unwrap();
                });

                let client_endpoint = IrohTransport::bind(iroh::SecretKey::generate())
                    .await
                    .unwrap();
                let transport = IrohTransport::connect(&client_endpoint, server_addr)
                    .await
                    .unwrap();
                let expected = Record {
                    id: "integration-record".into(),
                    version: 7,
                    ciphertext: vec![9, 8, 7, 6],
                };
                transport.send(&expected).await.unwrap();
                assert_eq!(transport.recv().await.unwrap(), expected);
                server.await.unwrap();
                client_endpoint.close().await;
                server_endpoint.close().await;
            })
            .await
            .expect("real iroh round-trip timed out");
        });
}

fn direct_addr(endpoint: &iroh::Endpoint) -> iroh::EndpointAddr {
    let port = endpoint
        .bound_sockets()
        .into_iter()
        .find(SocketAddr::is_ipv4)
        .unwrap()
        .port();
    iroh::EndpointAddr::new(endpoint.id()).with_ip_addr(SocketAddr::from(([127, 0, 0, 1], port)))
}

#[test]
fn real_pairing_handshake_leaves_device_b_with_exact_device_a_key_bytes() {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(30), async {
                let server_endpoint = bind_pairing(iroh::SecretKey::generate()).await.unwrap();
                let server_addr = direct_addr(&server_endpoint);
                let (encoded, server_code) = PairingCode::generate(server_endpoint.id());
                let client_code = PairingCode::decode(&encoded).unwrap();
                let accepting = server_endpoint.clone();
                let expected = [0xA7_u8; 32];
                let server = tokio::spawn(async move {
                    let connection = accept_pairing(&accepting).await.unwrap();
                    serve_pairing(connection, accepting.id(), &server_code, "device-a", || {
                        Ok(PairingKeyMaterial::new(expected))
                    })
                    .await
                    .unwrap()
                });

                let client_endpoint = bind_pairing(iroh::SecretKey::generate()).await.unwrap();
                let connection = connect_pairing(&client_endpoint, server_addr)
                    .await
                    .unwrap();
                let received =
                    request_pairing(connection, client_endpoint.id(), &client_code, "device-b")
                        .await
                        .unwrap();
                assert_eq!(received.key_material.as_bytes(), &expected);
                assert_eq!(received.peer.label, "device-a");
                let peer = server.await.unwrap();
                assert_eq!(peer.label, "device-b");
                client_endpoint.close().await;
                server_endpoint.close().await;
            })
            .await
            .expect("real pairing handshake timed out");
        });
}

#[test]
fn wrong_pairing_code_receives_no_key_material() {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(30), async {
                let server_endpoint = bind_pairing(iroh::SecretKey::generate()).await.unwrap();
                let server_addr = direct_addr(&server_endpoint);
                let (_encoded, server_code) = PairingCode::generate(server_endpoint.id());
                let (wrong_encoded, _) = PairingCode::generate(server_endpoint.id());
                let wrong_code = PairingCode::decode(&wrong_encoded).unwrap();
                let provider_called = Arc::new(AtomicBool::new(false));
                let server_provider_called = Arc::clone(&provider_called);
                let accepting = server_endpoint.clone();
                let server = tokio::spawn(async move {
                    let connection = accept_pairing(&accepting).await.unwrap();
                    serve_pairing(connection, accepting.id(), &server_code, "device-a", || {
                        server_provider_called.store(true, Ordering::SeqCst);
                        Ok(PairingKeyMaterial::new([0xD3_u8; 32]))
                    })
                    .await
                });

                let client_endpoint = bind_pairing(iroh::SecretKey::generate()).await.unwrap();
                let connection = connect_pairing(&client_endpoint, server_addr)
                    .await
                    .unwrap();
                let received = request_pairing(
                    connection,
                    client_endpoint.id(),
                    &wrong_code,
                    "unauthorized-device",
                )
                .await;
                assert!(
                    received.is_err(),
                    "wrong code unexpectedly received material"
                );
                assert!(server.await.unwrap().is_err(), "wrong proof was accepted");
                assert!(
                    !provider_called.load(Ordering::SeqCst),
                    "key provider ran before proof verification"
                );
                client_endpoint.close().await;
                server_endpoint.close().await;
            })
            .await
            .expect("wrong-code pairing test timed out");
        });
}
