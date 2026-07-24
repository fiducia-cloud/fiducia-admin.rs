//! Admin-plane local-first sync surface: the generic `{table}` write path,
//! write-key validation, request fingerprinting, the idempotency ledger, the
//! infra_operations write transaction, and cursor catch-up. Extracted from
//! main.rs; `use super::*` inherits AppState, entities, and error helpers.
#![allow(clippy::too_many_lines)]

use super::*;

/// One queued optimistic write from the sync client (mirrors the customer plane).
#[derive(Debug, Deserialize)]
pub(crate) struct SyncWriteRequest {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) op: Option<String>,
    #[serde(default)]
    pub(crate) payload: Option<Value>,
    #[serde(default)]
    pub(crate) base_version: Option<i64>,
    /// Client-minted durable identity used for both HTTP idempotency and exact
    /// realtime echo matching. Mutations require this either here or in the
    /// Idempotency-Key header; canonical clients send both.
    #[serde(default)]
    pub(crate) key: Option<String>,
}

/// The @fiducia/sync write path, generic in `{table}` (only `infra_operations` is
/// DB-wired today). Persists the queued optimistic write, returns the committed row
/// version (a shared `WriteAck`) so the client adopts it and clears `dirty`, and
/// broadcasts the change. Honors the client's Idempotency-Key so a retry replays
/// the original ack instead of re-running the UPDATE (which re-bumps version).
pub(crate) async fn sync_write(
    State(st): State<Arc<AppState>>,
    Path(table): Path<String>,
    headers: HeaderMap,
    Json(req): Json<SyncWriteRequest>,
) -> Response {
    let session = match require_admin_api(&headers, &st).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(error) = require_sync_write_security(&headers, &st, &session) {
        return request_security_error(error);
    }
    let idem_key = match validated_write_key(&headers, &req) {
        Ok(key) => key,
        Err(error) => return write_key_error(error),
    };
    let fingerprint = sync_write_fingerprint(&session, &table, &req);
    let outcome = match table.as_str() {
        "infra_operations" => sync_write_infra_operations(&st, &req, &idem_key, &fingerprint).await,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "unsupported_sync_table", "table": table })),
            )
                .into_response()
        }
    };
    match outcome {
        Ok(SyncWriteOutcome::Replay(version)) => ack(&req.id, version),
        Ok(SyncWriteOutcome::Committed(row)) => {
            // Publish only after the row update and idempotency outcome commit
            // together. A websocket echo must never expose a rolled-back write.
            broadcast_infra_change(&st, &row, Some(&idem_key));
            ack(&req.id, row.version)
        }
        Err(SyncWriteError::InvalidId) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_row_id" })),
        )
            .into_response(),
        Err(SyncWriteError::InvalidOperation) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_sync_operation" })),
        )
            .into_response(),
        Err(SyncWriteError::InvalidPayload) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_sync_payload" })),
        )
            .into_response(),
        Err(SyncWriteError::MissingBaseVersion) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "base_version_required" })),
        )
            .into_response(),
        Err(SyncWriteError::InvalidBaseVersion) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_base_version" })),
        )
            .into_response(),
        Err(SyncWriteError::VersionConflict { expected, actual }) => (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "version_conflict",
                "expected_version": expected,
                "actual_version": actual,
            })),
        )
            .into_response(),
        Err(SyncWriteError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "row_not_found" })),
        )
            .into_response(),
        Err(SyncWriteError::IdempotencyInFlight) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": "idempotency_in_flight" })),
        )
            .into_response(),
        Err(SyncWriteError::IdempotencyMismatch) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": "idempotency_key_reused" })),
        )
            .into_response(),
        Err(SyncWriteError::Database(err)) => dependency_error("sync_write_failed", err),
    }
}

/// Reconcile the HTTP Idempotency-Key with the same durable key carried in the
/// queued-write body. Canonical clients send both. A mismatch is rejected: the
/// server must never persist under one identity and publish a different one as
/// the purported own-echo token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WriteKeyError {
    Missing,
    Invalid,
    Mismatch,
}

pub(crate) fn validated_write_key(
    headers: &HeaderMap,
    request: &SyncWriteRequest,
) -> Result<String, WriteKeyError> {
    let mut header_values = headers.get_all("idempotency-key").iter();
    let header_key = match header_values.next() {
        Some(value) => Some(value.to_str().map_err(|_| WriteKeyError::Invalid)?),
        None => None,
    };
    if header_values.next().is_some() {
        return Err(WriteKeyError::Invalid);
    }
    let body_key = request.key.as_deref();

    for key in [header_key, body_key].into_iter().flatten() {
        if key.is_empty()
            || key.len() > MAX_WRITE_KEY_BYTES
            || !key.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(WriteKeyError::Invalid);
        }
    }
    if let (Some(header_key), Some(body_key)) = (header_key, body_key) {
        if header_key != body_key {
            return Err(WriteKeyError::Mismatch);
        }
    }

    header_key
        .or(body_key)
        .map(str::to_owned)
        .ok_or(WriteKeyError::Missing)
}

pub(crate) fn write_key_error(error: WriteKeyError) -> Response {
    let code = match error {
        WriteKeyError::Missing => "idempotency_key_required",
        WriteKeyError::Invalid => "invalid_write_key",
        WriteKeyError::Mismatch => "write_key_mismatch",
    };
    (StatusCode::BAD_REQUEST, Json(json!({ "error": code }))).into_response()
}

/// Bind an idempotency key to the full semantic write identity. Object keys are
/// hashed in sorted order so harmless JSON field reordering does not turn an
/// exact retry into a mismatch.
pub(crate) fn sync_write_fingerprint(
    session: &Session,
    table: &str,
    request: &SyncWriteRequest,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"fiducia-admin-sync-write-v1\0");
    fingerprint_field(&mut hasher, session.user_id.as_bytes());
    fingerprint_field(&mut hasher, table.as_bytes());
    fingerprint_field(&mut hasher, request.id.as_bytes());
    let operation = request.op.as_deref().unwrap_or("upsert");
    fingerprint_field(&mut hasher, operation.as_bytes());
    match request.base_version {
        Some(version) => {
            hasher.update([1]);
            hasher.update(version.to_be_bytes());
        }
        None => hasher.update([0]),
    }
    if operation == "delete" {
        fingerprint_json(&mut hasher, &Value::Null);
    } else if let Some(payload) = &request.payload {
        fingerprint_json(&mut hasher, payload);
    } else {
        fingerprint_json(&mut hasher, &json!({}));
    }
    format!("{:x}", hasher.finalize())
}

pub(crate) fn fingerprint_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

pub(crate) fn fingerprint_json(hasher: &mut Sha256, value: &Value) {
    match value {
        Value::Null => hasher.update([0]),
        Value::Bool(value) => hasher.update([1, u8::from(*value)]),
        Value::Number(value) => {
            hasher.update([2]);
            fingerprint_field(hasher, value.to_string().as_bytes());
        }
        Value::String(value) => {
            hasher.update([3]);
            fingerprint_field(hasher, value.as_bytes());
        }
        Value::Array(values) => {
            hasher.update([4]);
            hasher.update((values.len() as u64).to_be_bytes());
            for value in values {
                fingerprint_json(hasher, value);
            }
        }
        Value::Object(values) => {
            hasher.update([5]);
            hasher.update((values.len() as u64).to_be_bytes());
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|(key, _)| *key);
            for (key, value) in entries {
                fingerprint_field(hasher, key.as_bytes());
                fingerprint_json(hasher, value);
            }
        }
    }
}

/// Idempotency decision for a claimed/seen key.
pub(crate) enum Idem {
    Replay(i64),
    InFlight,
    Proceed,
}

/// Claim an idempotency key inside the SAME transaction as the protected row
/// update. A concurrent duplicate blocks on the unique key and then observes the
/// committed outcome; a failed owner rolls back both its claim and mutation.
pub(crate) async fn idempotency_claim(
    transaction: &DatabaseTransaction,
    key: &str,
    request_fingerprint: &str,
) -> Result<Idem, SyncWriteError> {
    let claimed = sync_idempotency_keys::Entity::insert(sync_idempotency_keys::ActiveModel {
        key: Set(key.to_string()),
        request_fingerprint: Set(Some(request_fingerprint.to_string())),
        ..Default::default()
    })
    .on_conflict(
        OnConflict::column(sync_idempotency_keys::Column::Key)
            .do_nothing()
            .to_owned(),
    )
    .exec_without_returning(transaction)
    .await
    .map_err(SyncWriteError::Database)?;
    if claimed > 0 {
        return Ok(Idem::Proceed);
    }
    let record = sync_idempotency_keys::Entity::find_by_id(key)
        .one(transaction)
        .await
        .map_err(SyncWriteError::Database)?
        .ok_or_else(|| {
            SyncWriteError::Database(DbErr::Custom(
                "idempotency key disappeared after unique-key conflict".to_string(),
            ))
        })?;
    idempotency_decision(
        record.request_fingerprint.as_deref(),
        record.committed_version,
        request_fingerprint,
    )
}

pub(crate) fn idempotency_decision(
    stored_fingerprint: Option<&str>,
    committed_version: Option<i64>,
    request_fingerprint: &str,
) -> Result<Idem, SyncWriteError> {
    let Some(stored_fingerprint) = stored_fingerprint else {
        // A pre-upgrade row cannot prove which request it protected. Replaying
        // its version for an arbitrary new payload would turn an old key into a
        // confused-deputy acknowledgement, so require the caller to mint a new
        // key instead.
        return Err(SyncWriteError::IdempotencyMismatch);
    };
    if stored_fingerprint != request_fingerprint {
        return Err(SyncWriteError::IdempotencyMismatch);
    }
    Ok(match committed_version {
        Some(version) => Idem::Replay(version),
        None => Idem::InFlight,
    })
}

/// Complete the claimed key in the surrounding row-mutation transaction.
pub(crate) async fn idempotency_complete(
    transaction: &DatabaseTransaction,
    key: &str,
    request_fingerprint: &str,
    version: i64,
) -> Result<(), SyncWriteError> {
    let result = sync_idempotency_keys::Entity::update_many()
        .col_expr(
            sync_idempotency_keys::Column::CommittedVersion,
            Expr::value(version),
        )
        .filter(sync_idempotency_keys::Column::Key.eq(key))
        .filter(sync_idempotency_keys::Column::RequestFingerprint.eq(request_fingerprint))
        .exec(transaction)
        .await
        .map_err(SyncWriteError::Database)?;
    if result.rows_affected != 1 {
        return Err(SyncWriteError::Database(DbErr::Custom(
            "idempotency completion did not update its claimed key".to_string(),
        )));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub(crate) struct CatchupParams {
    /// `since` remains an accepted alias for clients of the dormant pre-launch
    /// endpoint, but it now means a global sync sequence, never a row version.
    #[serde(default, alias = "since")]
    pub(crate) cursor: i64,
    #[serde(default)]
    pub(crate) limit: Option<u64>,
}

#[derive(Debug, Clone, Serialize, FromQueryResult)]
pub(crate) struct SyncCatchupChange {
    pub(crate) sequence: i64,
    #[serde(rename = "table")]
    pub(crate) table_name: String,
    pub(crate) op: String,
    pub(crate) id: String,
    pub(crate) version: i64,
    pub(crate) row: Option<Value>,
}

pub(crate) struct SyncCatchupPage {
    pub(crate) changes: Vec<SyncCatchupChange>,
    pub(crate) next_cursor: i64,
    pub(crate) has_more: bool,
}

/// Catch-up hydration returns a stable page of live-row upserts and durable
/// delete tombstones ordered by the plane-wide, commit-visible sync sequence.
pub(crate) async fn sync_catchup(
    State(st): State<Arc<AppState>>,
    Path(table): Path<String>,
    Query(params): Query<CatchupParams>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_admin_api(&headers, &st).await {
        return response;
    }
    let page_size = params.limit.unwrap_or(DEFAULT_CATCHUP_PAGE_SIZE);
    if params.cursor < 0 || page_size == 0 || page_size > MAX_CATCHUP_PAGE_SIZE {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_catchup_cursor_or_limit",
                "max_limit": MAX_CATCHUP_PAGE_SIZE,
            })),
        )
            .into_response();
    }
    let page = match table.as_str() {
        "infra_operations" => {
            let Some(db) = &st.db else {
                return dependency_error("database_unavailable", database_unavailable());
            };
            match catchup_infra_operations(db, params.cursor, page_size).await {
                Ok(page) => page,
                Err(err) => return dependency_error("sync_catchup_failed", err),
            }
        }
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "unsupported_sync_table", "table": table })),
            )
                .into_response()
        }
    };
    Json(json!({
        "table": table,
        "cursor": params.cursor,
        "next_cursor": page.next_cursor,
        "has_more": page.has_more,
        "changes": page.changes,
    }))
    .into_response()
}

/// Build the shared write-ack the @fiducia/sync client reconciles against.
pub(crate) fn ack(id: &str, committed_version: i64) -> Response {
    Json(WriteAck {
        id: id.to_string(),
        committed_version,
    })
    .into_response()
}

#[derive(Debug)]
pub(crate) enum SyncWriteOutcome {
    Replay(i64),
    Committed(Box<InfraOperationsRow>),
}

#[derive(Debug)]
pub(crate) enum SyncWriteError {
    InvalidId,
    InvalidOperation,
    InvalidPayload,
    MissingBaseVersion,
    InvalidBaseVersion,
    VersionConflict { expected: i64, actual: i64 },
    NotFound,
    IdempotencyInFlight,
    IdempotencyMismatch,
    Database(DbErr),
}

/// Persist one queued optimistic write and its idempotency result atomically.
/// The guarded UPDATE enforces `base_version`, the trigger bumps per-row version
/// and global sequence, and websocket publication happens only after commit.
pub(crate) async fn sync_write_infra_operations(
    st: &AppState,
    req: &SyncWriteRequest,
    write_key: &str,
    request_fingerprint: &str,
) -> Result<SyncWriteOutcome, SyncWriteError> {
    let id = Uuid::parse_str(&req.id).map_err(|_| SyncWriteError::InvalidId)?;
    let op = req.op.as_deref().unwrap_or("upsert");
    if !matches!(op, "upsert" | "delete") {
        return Err(SyncWriteError::InvalidOperation);
    }
    let expected_version = req.base_version.ok_or(SyncWriteError::MissingBaseVersion)?;
    if expected_version < 0 {
        return Err(SyncWriteError::InvalidBaseVersion);
    }
    let db = st
        .db
        .as_ref()
        .ok_or_else(|| SyncWriteError::Database(database_unavailable()))?;

    let transaction = db.begin().await.map_err(SyncWriteError::Database)?;
    let outcome = sync_write_infra_operations_in_transaction(
        &transaction,
        req,
        id,
        op,
        expected_version,
        write_key,
        request_fingerprint,
    )
    .await;
    match outcome {
        Ok(outcome) => {
            transaction
                .commit()
                .await
                .map_err(SyncWriteError::Database)?;
            Ok(outcome)
        }
        Err(error) => {
            transaction
                .rollback()
                .await
                .map_err(SyncWriteError::Database)?;
            Err(error)
        }
    }
}

pub(crate) async fn sync_write_infra_operations_in_transaction(
    transaction: &DatabaseTransaction,
    req: &SyncWriteRequest,
    id: Uuid,
    op: &str,
    expected_version: i64,
    write_key: &str,
    request_fingerprint: &str,
) -> Result<SyncWriteOutcome, SyncWriteError> {
    match idempotency_claim(transaction, write_key, request_fingerprint).await? {
        Idem::Replay(version) => return Ok(SyncWriteOutcome::Replay(version)),
        Idem::InFlight => return Err(SyncWriteError::IdempotencyInFlight),
        Idem::Proceed => {}
    }

    let current = infra_operations::Entity::find_by_id(id)
        .one(transaction)
        .await
        .map_err(SyncWriteError::Database)?
        .ok_or(SyncWriteError::NotFound)?;
    if current.version != expected_version {
        return Err(SyncWriteError::VersionConflict {
            expected: expected_version,
            actual: current.version,
        });
    }

    // The version predicate belongs to the UPDATE itself, not only to the read
    // above: two transactions may both observe the same base before either wins.
    let mut update = infra_operations::Entity::update_many()
        .filter(infra_operations::Column::Id.eq(id))
        .filter(infra_operations::Column::Version.eq(expected_version));

    if op == "delete" {
        // A control-plane op is an audit record, not a droppable row: a "delete"
        // marks it failed. Version still bumps via the trigger.
        update = update.col_expr(
            infra_operations::Column::Status,
            Expr::value("failed".to_string()),
        );
    } else {
        let payload = req.payload.clone().unwrap_or_else(|| json!({}));
        let status = payload
            .get("status")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let target_nodes = payload
            .get("target_nodes")
            .and_then(Value::as_i64)
            .map(i32::try_from)
            .transpose()
            .map_err(|_| SyncWriteError::InvalidPayload)?;
        let error = payload
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut changed = false;
        if let Some(status) = status {
            if !matches!(status.as_str(), "requested" | "applied" | "failed") {
                return Err(SyncWriteError::InvalidPayload);
            }
            update = update.col_expr(infra_operations::Column::Status, Expr::value(status));
            changed = true;
        }
        if let Some(target_nodes) = target_nodes {
            if target_nodes < 3 {
                return Err(SyncWriteError::InvalidPayload);
            }
            update = update.col_expr(
                infra_operations::Column::TargetNodes,
                Expr::value(Some(target_nodes)),
            );
            changed = true;
        }
        if let Some(error) = error {
            if error.len() > 500 {
                return Err(SyncWriteError::InvalidPayload);
            }
            update = update.col_expr(infra_operations::Column::Error, Expr::value(Some(error)));
            changed = true;
        }
        // Preserve the sync contract: even an empty patch is a committed write
        // whose trigger advances the row version.
        if !changed {
            update = update.col_expr(
                infra_operations::Column::Status,
                Expr::value(current.status),
            );
        }
    }

    let result = update
        .exec(transaction)
        .await
        .map_err(SyncWriteError::Database)?;
    if result.rows_affected != 1 {
        let actual = infra_operations::Entity::find_by_id(id)
            .one(transaction)
            .await
            .map_err(SyncWriteError::Database)?;
        return match actual {
            Some(row) => Err(SyncWriteError::VersionConflict {
                expected: expected_version,
                actual: row.version,
            }),
            None => Err(SyncWriteError::NotFound),
        };
    }
    let row = infra_operations::Entity::find_by_id(id)
        .one(transaction)
        .await
        .map_err(SyncWriteError::Database)?
        .ok_or(SyncWriteError::NotFound)?;
    idempotency_complete(transaction, write_key, request_fingerprint, row.version).await?;
    Ok(SyncWriteOutcome::Committed(Box::new(row)))
}

/// Load one bounded catch-up page in a single SQL snapshot. Splitting the live
/// row and tombstone reads into separate statements would allow a commit between
/// them to advance the returned cursor past a row the first statement did not see.
pub(crate) async fn catchup_infra_operations(
    db: &DatabaseConnection,
    cursor: i64,
    page_size: u64,
) -> Result<SyncCatchupPage, DbErr> {
    let fetch_limit = i64::try_from(page_size + 1)
        .map_err(|_| DbErr::Custom("catch-up page size overflow".to_string()))?;
    let statement = Statement::from_sql_and_values(
        DbBackend::Postgres,
        r#"
select live.sync_sequence as sequence,
       'infra_operations'::text as table_name,
       'upsert'::text as op,
       live.id::text as id,
       live.version as version,
       to_jsonb(live) as row
  from public.infra_operations live
 where live.sync_sequence > $1
union all
select tomb.sequence as sequence,
       tomb.table_name as table_name,
       'delete'::text as op,
       tomb.row_id as id,
       tomb.row_version as version,
       null::jsonb as row
  from public.sync_tombstones tomb
 where tomb.table_name = 'infra_operations'
   and tomb.sequence > $1
order by sequence
limit $2
"#,
        [cursor.into(), fetch_limit.into()],
    );
    let query_rows = db.query_all(statement).await?;
    let changes = query_rows
        .iter()
        .map(|row| SyncCatchupChange::from_query_result(row, ""))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(finish_catchup_page(changes, cursor, page_size))
}

pub(crate) fn finish_catchup_page(
    mut changes: Vec<SyncCatchupChange>,
    cursor: i64,
    page_size: u64,
) -> SyncCatchupPage {
    let page_size = page_size as usize;
    let has_more = changes.len() > page_size;
    if has_more {
        changes.truncate(page_size);
    }
    let next_cursor = changes.last().map_or(cursor, |change| change.sequence);
    SyncCatchupPage {
        changes,
        next_cursor,
        has_more,
    }
}
