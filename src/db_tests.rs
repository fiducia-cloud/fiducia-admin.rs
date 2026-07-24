//! Live-database (skips without TEST_DATABASE_URL) integration tests. Extracted verbatim from main.rs;
//! `use super::*` resolves to the crate root exactly as when inline.

use super::*;
use sea_orm::ConnectionTrait;

const SCHEMA: &str = include_str!("../../fiducia-interfaces/sql/admin.sql");

// Multiple db_tests target one TEST_DATABASE_URL. `CREATE TABLE IF NOT
// EXISTS` is not safe against a *concurrent* create (both pass the existence
// check, then collide on pg_type), so apply the schema exactly once across
// the whole test binary rather than per-test.
static SCHEMA_READY: tokio::sync::Mutex<bool> = tokio::sync::Mutex::const_new(false);

async fn prepare_schema(db: &DatabaseConnection) {
    let mut ready = SCHEMA_READY.lock().await;
    if !*ready {
        db.execute_unprepared(SCHEMA)
            .await
            .expect("apply admin.sql");
        *ready = true;
    }
}

fn state_with(db: DatabaseConnection) -> AppState {
    AppState {
        auth_url: "x".into(),
        brain_url: "x".into(),
        supabase_url: "https://example.supabase.co".into(),
        supabase_publishable_key: "test-publishable-key".into(),
        db: Some(db),
        stream_tx: broadcast::channel(4).0,
        request_security: test_request_security(),
        prometheus_url: None,
        loki_url: None,
        grafana_public_url: None,
        node_urls: Vec::new(),
    }
}

// One test, one connection, one runtime: SeaORM's async connection pool is
// runtime-bound, so the whole durability check deliberately shares one test.
#[tokio::test]
async fn sync_durability_against_real_postgres() {
    let Some(url) = std::env::var("TEST_DATABASE_URL")
        .ok()
        .filter(|v| !v.is_empty())
    else {
        eprintln!("skip sync_durability_against_real_postgres: TEST_DATABASE_URL unset");
        return;
    };
    let mut options = ConnectOptions::new(url);
    options.max_connections(4);
    let db = Database::connect(options)
        .await
        .expect("connect TEST_DATABASE_URL");
    // Raw SQL here applies the canonical gated-test schema; behavioral CRUD
    // below uses SeaORM, while production catch-up owns one reviewed UNION so
    // live rows and tombstones are read in a single database snapshot.
    prepare_schema(&db).await;
    let st = state_with(db.clone());

    // --- Durable idempotency: rollback -> commit -> exact replay ------------
    let row_id = Uuid::new_v4();
    let key = format!("admin-sync-{}", Uuid::new_v4().simple());
    let request = SyncWriteRequest {
        id: row_id.to_string(),
        op: Some("upsert".into()),
        payload: Some(json!({ "status": "applied" })),
        base_version: Some(1),
        key: Some(key.clone()),
    };
    let operator =
        Session::test_admin_bearer("00000000-0000-0000-0000-000000000001", "verified.jwt");
    let fingerprint = sync_write_fingerprint(&operator, "infra_operations", &request);

    assert!(matches!(
        sync_write_infra_operations(&st, &request, &key, &fingerprint).await,
        Err(SyncWriteError::NotFound)
    ));
    assert!(
        sync_idempotency_keys::Entity::find_by_id(&key)
            .one(&db)
            .await
            .unwrap()
            .is_none(),
        "a failed row mutation rolls its key claim back"
    );

    infra_operations::ActiveModel {
        id: Set(row_id),
        action: Set("scale".to_string()),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();
    let committed_version = match sync_write_infra_operations(&st, &request, &key, &fingerprint)
        .await
        .unwrap()
    {
        SyncWriteOutcome::Committed(row) => row.version,
        SyncWriteOutcome::Replay(_) => panic!("first successful write must commit"),
    };
    let ledger = sync_idempotency_keys::Entity::find_by_id(&key)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ledger.request_fingerprint.as_deref(), Some(&*fingerprint));
    assert_eq!(ledger.committed_version, Some(committed_version));

    // Survives a restart and replays only the exact original request.
    let fresh = state_with(db.clone());
    assert!(matches!(
        sync_write_infra_operations(&fresh, &request, &key, &fingerprint).await,
        Ok(SyncWriteOutcome::Replay(version)) if version == committed_version
    ));
    let changed = SyncWriteRequest {
        id: request.id.clone(),
        op: request.op.clone(),
        payload: Some(json!({ "status": "failed" })),
        base_version: request.base_version,
        key: request.key.clone(),
    };
    let changed_fingerprint = sync_write_fingerprint(&operator, "infra_operations", &changed);
    assert!(matches!(
        sync_write_infra_operations(&fresh, &changed, &key, &changed_fingerprint).await,
        Err(SyncWriteError::IdempotencyMismatch)
    ));

    // A distinct stale write must lose the version CAS and roll its newly
    // claimed idempotency key back, while the exact old request above replays.
    let stale_key = format!("admin-sync-stale-{}", Uuid::new_v4().simple());
    let stale = SyncWriteRequest {
        key: Some(stale_key.clone()),
        ..SyncWriteRequest {
            id: request.id.clone(),
            op: request.op.clone(),
            payload: Some(json!({ "status": "failed" })),
            base_version: Some(1),
            key: None,
        }
    };
    let stale_fingerprint = sync_write_fingerprint(&operator, "infra_operations", &stale);
    assert!(matches!(
        sync_write_infra_operations(&fresh, &stale, &stale_key, &stale_fingerprint).await,
        Err(SyncWriteError::VersionConflict { expected: 1, actual })
            if actual == committed_version
    ));
    assert!(
        sync_idempotency_keys::Entity::find_by_id(&stale_key)
            .one(&db)
            .await
            .unwrap()
            .is_none(),
        "a failed CAS rolls its key claim back"
    );

    // --- Global cursor: stable pages include v1 inserts and delete tombstones.
    let clock = db
        .query_one(Statement::from_string(
            DbBackend::Postgres,
            "select last_sequence from public.sync_clock".to_string(),
        ))
        .await
        .unwrap()
        .unwrap();
    let start_cursor: i64 = clock.try_get("", "last_sequence").unwrap();
    let a = infra_operations::ActiveModel {
        action: Set("scale".to_string()),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();
    let b = infra_operations::ActiveModel {
        action: Set("drain".to_string()),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();
    let a_id = a.id;
    let b_id = b.id;
    let mut active: infra_operations::ActiveModel = a.into();
    active.status = Set("applied".to_string());
    active.update(&db).await.unwrap(); // bump `a` to version 2
    infra_operations::Entity::delete_by_id(b_id)
        .exec(&db)
        .await
        .unwrap();
    let c = infra_operations::ActiveModel {
        action: Set("snapshot".to_string()),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();

    let mut cursor = start_cursor;
    let mut changes = Vec::new();
    loop {
        let page = catchup_infra_operations(&db, cursor, 1).await.unwrap();
        assert!(page.changes.iter().all(|change| change.sequence > cursor));
        changes.extend(page.changes);
        if !page.has_more {
            cursor = page.next_cursor;
            break;
        }
        assert!(page.next_cursor > cursor);
        cursor = page.next_cursor;
    }
    assert!(
        changes
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence),
        "global sequences are unique and strictly ordered"
    );
    assert!(changes.iter().any(|change| {
        change.id == a_id.to_string() && change.op == "upsert" && change.version == 2
    }));
    assert!(changes.iter().any(|change| {
        change.id == b_id.to_string()
            && change.op == "delete"
            && change.version == 2
            && change.row.is_none()
    }));
    assert!(
        changes.iter().any(|change| {
            change.id == c.id.to_string() && change.op == "upsert" && change.version == 1
        }),
        "a later v1 insert is visible after higher per-row versions"
    );
    assert_eq!(
        cursor,
        changes
            .last()
            .map_or(start_cursor, |change| change.sequence)
    );
}

#[tokio::test]
async fn publishing_a_notice_writes_audit_and_bumps_version() {
    let Some(url) = std::env::var("TEST_DATABASE_URL")
        .ok()
        .filter(|v| !v.is_empty())
    else {
        eprintln!("skip publishing_a_notice...: TEST_DATABASE_URL unset");
        return;
    };
    let mut options = ConnectOptions::new(url);
    options.max_connections(4);
    let db = Database::connect(options)
        .await
        .expect("connect TEST_DATABASE_URL");
    prepare_schema(&db).await;
    let st = state_with(db.clone());

    // dev-admin path: operator_id is None but the transaction still records
    // both the notice and its audit row.
    let session = Session::test_admin_bearer("dev-admin", "verified.jwt");
    let before = recent_admin_audit(&st, 100).await.unwrap().len();
    let notice = record_notice(
        &st,
        &session,
        "warning",
        "Maintenance 02:00 UTC",
        "Brief blip",
    )
    .await
    .expect("publish notice");
    // Trigger-assigned sync fields.
    assert_eq!(notice.version, 1);
    assert!(notice.sync_sequence > 0);
    assert!(notice.active);

    // The notice is listed and an audit row was written in the same commit.
    let listed = recent_notices(&st, 50).await.unwrap();
    assert!(listed.iter().any(|n| n.id == notice.id));
    let after = recent_admin_audit(&st, 100).await.unwrap();
    assert_eq!(after.len(), before + 1);
    assert!(after.iter().any(|a| a.action == "notice.published"
        && a.target.as_deref() == Some(notice.id.to_string().as_str())));
}
