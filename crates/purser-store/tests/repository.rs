use purser_store::Store;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn repository_versions_ciphertext_and_returns_only_latest_active_value() {
    let store = Store::open_in_memory().unwrap();
    let id = store
        .upsert_secret("DATABASE_URL", "test", Some("database"), true)
        .unwrap();
    assert_eq!(store.add_secret_version(&id, b"ciphertext-v1").unwrap(), 1);
    assert_eq!(store.add_secret_version(&id, b"ciphertext-v2").unwrap(), 2);

    let summaries = store.list_secrets("test").unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].name, "DATABASE_URL");
    assert!(summaries[0].configured);

    assert_eq!(
        store.get_active_versions("test").unwrap(),
        vec![("DATABASE_URL".to_owned(), b"ciphertext-v2".to_vec())]
    );
}

#[test]
fn migrations_are_idempotent_when_reopening_a_file() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("purser-store-{unique}.db"));
    {
        let store = Store::open_at(&path).unwrap();
        store.upsert_secret("TOKEN", "local", None, false).unwrap();
    }
    {
        let reopened = Store::open_at(&path).unwrap();
        assert_eq!(reopened.list_secrets("local").unwrap().len(), 1);
    }
    std::fs::remove_file(path).unwrap();
}
