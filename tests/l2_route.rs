use std::net::Ipv4Addr;

use shabdiz::carrier::l2::pick_route;

const LAPTOP: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
zedsecure0\t00000000\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0
enp3s0\t00000000\t0164A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
enp3s0\t3F061C51\t0164A8C0\t0007\t0\t0\t0\tFFFFFFFF\t0\t0\t0
zedsecure0\t00000080\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0
enp3s0\t0064A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";

#[test]
fn a_host_route_beats_the_vpn_halves_and_the_default() {
    assert_eq!(
        pick_route(LAPTOP, Ipv4Addr::new(81, 28, 6, 63)),
        Some(("enp3s0".to_string(), Ipv4Addr::new(192, 168, 100, 1)))
    );
}

#[test]
fn without_a_host_route_the_vpn_half_wins_over_the_default() {
    assert_eq!(
        pick_route(LAPTOP, Ipv4Addr::new(135, 148, 204, 60)).map(|(i, _)| i),
        Some("zedsecure0".to_string()),
        "a /1 is longer than a /0, exactly as the kernel decides"
    );
}

#[test]
fn an_on_link_peer_is_its_own_next_hop() {
    assert_eq!(
        pick_route(LAPTOP, Ipv4Addr::new(192, 168, 100, 20)),
        Some(("enp3s0".to_string(), Ipv4Addr::new(192, 168, 100, 20)))
    );
}

#[test]
fn the_lower_metric_wins_between_equal_prefixes() {
    let two_defaults = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
eth0\t00000000\t0164A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
";
    assert_eq!(
        pick_route(two_defaults, Ipv4Addr::new(8, 8, 8, 8)).map(|(i, _)| i),
        Some("eth0".to_string())
    );
}
