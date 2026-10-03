use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use microsandbox_network::policy::{
    Action, Destination, DestinationGroup, HostnameSource, NetworkPolicy, Protocol, Rule,
};
use microsandbox_network::shared::{ResolvedHostnameFamily, SharedState};

fn outcomes(ip: &str, bind_dns: bool) -> [Action; 2] {
    let shared = SharedState::new(4);
    shared.set_nat64_prefixes(vec!["64:ff9b::/96".parse().unwrap()]);
    let ip: IpAddr = ip.parse().unwrap();
    if bind_dns {
        shared.cache_resolved_hostname(
            "allowed.example",
            if ip.is_ipv6() {
                ResolvedHostnameFamily::Ipv6
            } else {
                ResolvedHostnameFamily::Ipv4
            },
            [ip],
            Duration::from_secs(60),
        );
    }
    let policy = NetworkPolicy {
        default_egress: Action::Deny,
        default_ingress: Action::Allow,
        rules: vec![
            Rule::deny_egress(Destination::Group(DestinationGroup::Metadata)),
            Rule::deny_egress(Destination::Cidr("169.254.169.254/32".parse().unwrap())),
            Rule::deny_egress(Destination::Group(DestinationGroup::Private)),
            Rule::allow_egress(Destination::Domain("allowed.example".parse().unwrap())),
        ],
    };
    let dst = SocketAddr::new(ip, 443);
    [
        policy.evaluate_egress(dst, Protocol::Tcp, &shared),
        policy
            .evaluate_egress_with_source(
                dst,
                Protocol::Tcp,
                &shared,
                HostnameSource::Sni("allowed.example"),
            )
            .into(),
    ]
}

#[test]
fn domain_dns_binding_cannot_allow_translated_metadata() {
    assert_eq!(outcomes("64:ff9b::a9fe:a9fe", true), [Action::Deny; 2]);
}

#[test]
fn domain_dns_binding_cannot_allow_translated_private() {
    assert_eq!(outcomes("64:ff9b::a00:1", true), [Action::Deny; 2]);
}

#[test]
fn direct_metadata_remains_denied() {
    assert_eq!(outcomes("169.254.169.254", true), [Action::Deny; 2]);
}

#[test]
fn ordinary_bound_public_destination_remains_allowed() {
    assert_eq!(outcomes("8.8.8.8", true), [Action::Allow; 2]);
}

#[test]
fn translated_destination_without_domain_dns_binding_is_denied() {
    assert_eq!(outcomes("64:ff9b::a9fe:a9fe", false), [Action::Deny; 2]);
}
