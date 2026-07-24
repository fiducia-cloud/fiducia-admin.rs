//! Admin sync WebSocket: broadcasting infra_operations changes as
//! `fiducia:sync` frames and the per-connection stream loop. Extracted from main.rs.

use super::*;

/// Broadcast a single infra_operations upsert as a `fiducia:sync` frame, built from
/// the shared fiducia-sync-core ChangeEvent so server and client agree on one shape.
pub(crate) fn broadcast_infra_change(
    st: &AppState,
    row: &InfraOperationsRow,
    write_key: Option<&str>,
) {
    let change = ChangeEvent {
        table: "infra_operations".to_string(),
        op: ChangeOp::Upsert,
        id: row.id.to_string(),
        version: row.version,
        row: serde_json::to_value(row).unwrap_or_default(),
        at_ms: unix_epoch_ms() as i64,
        write_key: write_key.map(str::to_owned),
    };
    let frame = json!({ "event": "fiducia:sync", "changes": [change] });
    let _ = st.stream_tx.send(frame.to_string());
}

pub(crate) fn unix_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// The admin-plane sync socket: on connect, sends a hello frame, then forwards
/// every `fiducia:sync` broadcast frame verbatim (mirrors fiducia-backend's WS).
pub(crate) async fn admin_ws(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if let Err(response) = require_admin_api(&headers, &st).await {
        return response;
    }
    if let Err(error) = st.request_security.require_same_origin(&headers) {
        return request_security_error(error);
    }
    let rx = st.stream_tx.subscribe();
    ws.on_upgrade(move |socket| admin_ws_stream(socket, rx))
}

/// Idle keepalive for the admin sync socket. Without a server-side ping an idle
/// `/admin/ws` behind an LB/ingress is reaped after its idle timeout with no
/// signal to either end; the tick also detects a half-open peer (the send fails)
/// so the task exits instead of leaking. Mirrors the customer plane's cadence.
pub(crate) const ADMIN_WS_HEARTBEAT_SECS: u64 = 15;

pub(crate) async fn admin_ws_stream(mut socket: WebSocket, mut rx: broadcast::Receiver<String>) {
    let hello = json!({ "event": "connected", "service": SERVICE }).to_string();
    if socket.send(Message::Text(hello)).await.is_err() {
        return;
    }
    let mut heartbeat = tokio::time::interval(Duration::from_secs(ADMIN_WS_HEARTBEAT_SECS));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            frame = rx.recv() => match frame {
                Ok(payload) => {
                    if socket.send(Message::Text(payload)).await.is_err() {
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    // The client fell behind the bounded broadcast buffer and
                    // permanently lost those `ChangeEvent` frames — its IndexedDB
                    // mirror is now missing rows. Continuing silently from the
                    // newest frame leaves it wrong with no signal. Tell it to
                    // re-run its per-table catch-up (`/api/admin/sync/:table`)
                    // instead; if we can't even deliver that, drop the socket so
                    // the client reconnects and resyncs from scratch.
                    tracing::warn!(skipped, "admin sync stream lagged; signalling client resync");
                    let resync = json!({ "event": "fiducia:resync", "reason": "lagged" }).to_string();
                    if socket.send(Message::Text(resync)).await.is_err() {
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
            _ = heartbeat.tick() => {
                if socket.send(Message::Ping(Vec::new())).await.is_err() {
                    return;
                }
            }
            msg = socket.recv() => match msg {
                Some(Ok(Message::Close(_))) | None => return,
                Some(Err(_)) => return,
                // Pong/Text/Binary from the client are ignored; the socket is
                // server-push only. Receiving keeps the half-open detection live.
                _ => {}
            }
        }
    }
}
