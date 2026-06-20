//! Client-IP access control: allow and deny lists with CIDR support.

use ipnet::IpNet;
use std::net::IpAddr;

/// Allow/deny rules evaluated against a client IP.
#[derive(Debug, Default)]
pub struct AccessControl {
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
}

impl AccessControl {
    /// Build access rules from allow and deny entries, each a bare IP
    /// (`1.2.3.4`) or a CIDR block (`10.0.0.0/8`).
    ///
    /// # Errors
    /// Returns the offending entry if it is not a valid IP or CIDR.
    pub fn parse(allow: &[String], deny: &[String]) -> Result<Self, String> {
        Ok(Self {
            allow: parse_nets(allow)?,
            deny: parse_nets(deny)?,
        })
    }

    /// Whether any rules are configured (otherwise every client is allowed).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }

    /// Whether `ip` is permitted: denied if it matches any deny rule, or if an
    /// allow list is present and it matches none of it.
    #[must_use]
    pub fn allows(&self, ip: IpAddr) -> bool {
        if self.deny.iter().any(|net| net.contains(&ip)) {
            return false;
        }
        if !self.allow.is_empty() && !self.allow.iter().any(|net| net.contains(&ip)) {
            return false;
        }
        true
    }
}

fn parse_nets(entries: &[String]) -> Result<Vec<IpNet>, String> {
    entries.iter().map(|entry| parse_net(entry)).collect()
}

/// Parse a single entry as a CIDR block or a bare host IP.
fn parse_net(entry: &str) -> Result<IpNet, String> {
    if let Ok(net) = entry.parse::<IpNet>() {
        return Ok(net);
    }
    if let Ok(ip) = entry.parse::<IpAddr>() {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        return IpNet::new(ip, prefix).map_err(|_| entry.to_owned());
    }
    Err(entry.to_owned())
}

#[cfg(test)]
mod tests {
    use super::AccessControl;

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn deny_list_blocks_matching_ip() {
        let ac = AccessControl::parse(&[], &["1.2.3.4".to_owned()]).unwrap();
        assert!(!ac.allows(ip("1.2.3.4")));
        assert!(ac.allows(ip("5.6.7.8")));
    }

    #[test]
    fn deny_list_supports_cidr() {
        let ac = AccessControl::parse(&[], &["10.0.0.0/8".to_owned()]).unwrap();
        assert!(!ac.allows(ip("10.1.2.3")));
        assert!(ac.allows(ip("11.0.0.1")));
    }

    #[test]
    fn allow_list_blocks_everything_else() {
        let ac = AccessControl::parse(&["192.168.0.0/16".to_owned()], &[]).unwrap();
        assert!(ac.allows(ip("192.168.5.5")));
        assert!(!ac.allows(ip("8.8.8.8")));
    }

    #[test]
    fn deny_takes_precedence_over_allow() {
        let ac =
            AccessControl::parse(&["10.0.0.0/8".to_owned()], &["10.0.0.5".to_owned()]).unwrap();
        assert!(ac.allows(ip("10.0.0.6")));
        assert!(!ac.allows(ip("10.0.0.5")));
    }

    #[test]
    fn no_rules_allows_all() {
        let ac = AccessControl::default();
        assert!(ac.is_empty());
        assert!(ac.allows(ip("1.2.3.4")));
    }

    #[test]
    fn invalid_entry_is_rejected() {
        assert!(AccessControl::parse(&[], &["not-an-ip".to_owned()]).is_err());
    }
}
