use microsandbox_network::config::{NetworkBuilder, NetworkConfig};
use microsandbox_types::NetworkSpec;
use serde_json::json;

#[test]
fn stored_network_config_distinguishes_missing_from_empty() {
    let omitted: NetworkConfig = serde_json::from_value(json!({})).unwrap();
    let empty: NetworkConfig = serde_json::from_value(json!({"nat64_prefixes": []})).unwrap();
    assert_eq!(
        omitted.nat64_prefixes,
        vec!["64:ff9b::/96".parse().unwrap()]
    );
    assert!(empty.nat64_prefixes.is_empty());
}

#[test]
fn stored_network_spec_distinguishes_missing_from_empty() {
    let mut saved = serde_json::to_value(NetworkSpec::default()).unwrap();
    saved.as_object_mut().unwrap().remove("nat64_prefixes");
    let omitted: NetworkSpec = serde_json::from_value(saved.clone()).unwrap();
    saved["nat64_prefixes"] = json!([]);
    let empty: NetworkSpec = serde_json::from_value(saved).unwrap();
    assert_eq!(
        omitted.nat64_prefixes,
        vec!["64:ff9b::/96".parse().unwrap()]
    );
    assert!(empty.nat64_prefixes.is_empty());
}

#[test]
fn additive_builder_keeps_default_and_deduplicates_custom_prefix() {
    let custom = "2001:db8:64::/96".parse().unwrap();
    let config = NetworkBuilder::new()
        .nat64_prefix(custom)
        .nat64_prefix(custom)
        .build()
        .unwrap();
    assert_eq!(config.nat64_prefixes.len(), 2);
    assert!(
        config
            .nat64_prefixes
            .contains(&"64:ff9b::/96".parse().unwrap())
    );
    assert!(config.nat64_prefixes.contains(&custom));
}

#[test]
fn builder_from_existing_empty_config_does_not_reinsert_default() {
    let saved: NetworkConfig = serde_json::from_value(json!({"nat64_prefixes": []})).unwrap();
    assert!(
        NetworkBuilder::from_config(saved)
            .build()
            .unwrap()
            .nat64_prefixes
            .is_empty()
    );
}

#[test]
fn builder_revalidates_prefix_from_stored_config() {
    let saved: NetworkConfig =
        serde_json::from_value(json!({"nat64_prefixes": ["64:ff9b::/64"]})).unwrap();
    assert!(matches!(
        NetworkBuilder::from_config(saved).build(),
        Err(microsandbox_network::policy::BuildError::InvalidNat64Prefix { .. })
    ));
}
