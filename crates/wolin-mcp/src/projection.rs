use std::collections::{BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use wolin_core::{Principal, WebId};
use wolin_storage::rdf_model::{Literal, Subject, Term, Triple};

const MAX_QUOTED_TRIPLE_DEPTH: usize = 16;

/// Sensitive Personal Identifiable Information (PII) categories governed by
/// Wolin agent selective-disclosure scopes (`pii:<category>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiCategory {
    Email,
    Phone,
    Address,
    Identity,
}

impl PiiCategory {
    pub fn all() -> [Self; 4] {
        [Self::Email, Self::Phone, Self::Address, Self::Identity]
    }
}

/// Server-side selective-disclosure policy and custom ontology predicate classifications.
#[derive(Debug, Clone, Default)]
pub struct DisclosurePolicy {
    custom_pii_predicates: HashMap<String, PiiCategory>,
    custom_secret_predicates: HashSet<String>,
    agent_allowed_categories: HashMap<(String, WebId), BTreeSet<PiiCategory>>,
}

impl DisclosurePolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Classify an RDF predicate IRI under a specific [`PiiCategory`].
    pub fn register_pii_predicate(
        &mut self,
        predicate_iri: impl Into<String>,
        category: PiiCategory,
    ) {
        self.custom_pii_predicates
            .insert(predicate_iri.into(), category);
    }

    /// Classify an RDF predicate IRI as a cryptographic/API secret (never disclosed to agents).
    pub fn register_secret_predicate(&mut self, predicate_iri: impl Into<String>) {
        self.custom_secret_predicates.insert(predicate_iri.into());
    }

    /// Restrict the maximum PII categories that `(agent_id, delegated_by)` may ever receive,
    /// attenuating any broader `pii:*` claims carried in the agent's token scope.
    pub fn set_agent_allowed_categories(
        &mut self,
        agent_id: impl Into<String>,
        delegated_by: WebId,
        categories: impl IntoIterator<Item = PiiCategory>,
    ) {
        self.agent_allowed_categories.insert(
            (agent_id.into(), delegated_by),
            categories.into_iter().collect(),
        );
    }
}

/// Effective per-request disclosure profile resolved from caller [`Principal`] and [`DisclosurePolicy`].
#[derive(Debug, Clone)]
pub struct DisclosureProfile {
    pub zero_pii_enforced: bool,
    pub redact_secrets: bool,
    pub allowed_categories: BTreeSet<PiiCategory>,
}

impl DisclosureProfile {
    pub fn resolve(principal: &Principal, policy: &DisclosurePolicy) -> Self {
        match principal {
            Principal::User { .. } => Self {
                zero_pii_enforced: false,
                redact_secrets: false,
                allowed_categories: PiiCategory::all().into_iter().collect(),
            },
            Principal::Anonymous => Self {
                zero_pii_enforced: true,
                redact_secrets: true,
                allowed_categories: BTreeSet::new(),
            },
            Principal::Agent {
                agent_id,
                delegated_by,
                scope,
            } => {
                let mut from_scope = parse_agent_disclosure_scopes(scope);
                if let Some(ceiling) = policy
                    .agent_allowed_categories
                    .get(&(agent_id.clone(), delegated_by.clone()))
                {
                    from_scope = from_scope.intersection(ceiling).copied().collect();
                }
                Self {
                    zero_pii_enforced: true,
                    redact_secrets: true,
                    allowed_categories: from_scope,
                }
            }
        }
    }
}

/// Output of projecting an RDF triple slice through a [`DisclosureProfile`].
#[derive(Debug, Clone)]
pub struct ProjectedTriples {
    pub triples: Vec<Triple>,
    pub redacted_triples: usize,
}

/// Apply recursive predicate-level selective disclosure (including RDF-star quoted triples)
/// and literal-level Zero-PII scrubbing prior to loading triples into an agent's SPARQL sandbox
/// or serializing RDF reads.
pub fn project_triples(
    triples: &[Triple],
    profile: &DisclosureProfile,
    policy: &DisclosurePolicy,
) -> ProjectedTriples {
    if !profile.zero_pii_enforced && !profile.redact_secrets {
        return ProjectedTriples {
            triples: triples.to_vec(),
            redacted_triples: 0,
        };
    }

    let mut out = Vec::with_capacity(triples.len());
    let mut redacted_count = 0usize;

    for triple in triples {
        match project_single_triple(triple, profile, policy, 0) {
            Some((clean_triple, was_scrubbed)) => {
                if was_scrubbed {
                    redacted_count += 1;
                }
                out.push(clean_triple);
            }
            None => {
                redacted_count += 1;
            }
        }
    }

    ProjectedTriples {
        triples: out,
        redacted_triples: redacted_count,
    }
}

fn project_single_triple(
    triple: &Triple,
    profile: &DisclosureProfile,
    policy: &DisclosurePolicy,
    depth: usize,
) -> Option<(Triple, bool)> {
    if depth > MAX_QUOTED_TRIPLE_DEPTH {
        return None;
    }

    let pred_iri = triple.predicate.as_str();
    if profile.redact_secrets && is_secret_predicate(pred_iri, policy) {
        return None;
    }

    if let Some(cat) = classify_pii_predicate(pred_iri, policy) {
        if !profile.allowed_categories.contains(&cat) {
            return None;
        }
    }

    let mut modified = false;

    let clean_subject = match &triple.subject {
        Subject::NamedNode(n) => {
            if iri_violates_pii(n.as_str(), profile) {
                return None;
            }
            Subject::NamedNode(n.clone())
        }
        Subject::BlankNode(b) => Subject::BlankNode(b.clone()),
        Subject::Triple(inner) => {
            let (projected_inner, inner_mod) =
                project_single_triple(inner, profile, policy, depth + 1)?;
            modified |= inner_mod;
            Subject::Triple(Box::new(projected_inner))
        }
    };

    let clean_object = match &triple.object {
        Term::NamedNode(n) => {
            if iri_violates_pii(n.as_str(), profile) {
                return None;
            }
            Term::NamedNode(n.clone())
        }
        Term::BlankNode(b) => Term::BlankNode(b.clone()),
        Term::Literal(lit) => {
            let raw_val = lit.value();
            let scrubbed = scrub_literal_text(raw_val, profile);
            if scrubbed != raw_val {
                modified = true;
                Term::Literal(rebuild_literal(lit, &scrubbed))
            } else {
                Term::Literal(lit.clone())
            }
        }
        Term::Triple(inner) => {
            let (projected_inner, inner_mod) =
                project_single_triple(inner, profile, policy, depth + 1)?;
            modified |= inner_mod;
            Term::Triple(Box::new(projected_inner))
        }
    };

    Some((
        Triple::new(clean_subject, triple.predicate.clone(), clean_object),
        modified,
    ))
}

fn parse_agent_disclosure_scopes(scopes: &[String]) -> BTreeSet<PiiCategory> {
    let mut set = BTreeSet::new();
    for raw in scopes {
        match raw.trim() {
            "pii:full" | "pii:all" | "pii:*" | "disclosure:full" => {
                set.extend(PiiCategory::all());
            }
            "pii:email" | "disclosure:email" => {
                set.insert(PiiCategory::Email);
            }
            "pii:phone" | "disclosure:phone" => {
                set.insert(PiiCategory::Phone);
            }
            "pii:address" | "disclosure:address" => {
                set.insert(PiiCategory::Address);
            }
            "pii:identity" | "disclosure:identity" => {
                set.insert(PiiCategory::Identity);
            }
            _ => {}
        }
    }
    set
}

fn iri_local_name(iri: &str) -> &str {
    let after_hash = iri.rsplit('#').next().unwrap_or(iri);
    if after_hash.len() < iri.len() {
        return after_hash;
    }
    iri.trim_end_matches('/').rsplit('/').next().unwrap_or(iri)
}

fn is_secret_predicate(pred_iri: &str, policy: &DisclosurePolicy) -> bool {
    if policy.custom_secret_predicates.contains(pred_iri) {
        return true;
    }
    let local = iri_local_name(pred_iri).to_ascii_lowercase();
    matches!(
        local.as_str(),
        "secretapikey"
            | "apikey"
            | "api_key"
            | "api-key"
            | "privatekey"
            | "private_key"
            | "secretkey"
            | "secret_key"
            | "password"
            | "passwd"
            | "accesstoken"
            | "access_token"
            | "refreshtoken"
            | "refresh_token"
            | "clientsecret"
            | "client_secret"
            | "bearertoken"
            | "bearer_token"
            | "masterkey"
            | "signingkey"
            | "seedphrase"
            | "mnemonic"
            | "secret"
    )
}

fn classify_pii_predicate(pred_iri: &str, policy: &DisclosurePolicy) -> Option<PiiCategory> {
    if let Some(&cat) = policy.custom_pii_predicates.get(pred_iri) {
        return Some(cat);
    }
    let local = iri_local_name(pred_iri).to_ascii_lowercase();
    match local.as_str() {
        "mbox" | "mbox_sha1sum" | "email" | "hasemail" | "emailaddress" | "workemail"
        | "personalemail" => Some(PiiCategory::Email),
        "phone" | "telephone" | "hastelephone" | "tel" | "mobile" | "phonenumber" | "faxnumber" => {
            Some(PiiCategory::Phone)
        }
        "address" | "hasaddress" | "streetaddress" | "street-address" | "homeaddress"
        | "postalcode" | "postal-code" | "zipcode" | "latitude" | "longitude" | "lat" | "long" => {
            Some(PiiCategory::Address)
        }
        "ssn" | "taxid" | "nationalid" | "residentid" | "passportnumber" | "driverlicense"
        | "birthdate" | "birthday" | "bday" | "dateofbirth" | "dob" | "bankaccount" | "iban"
        | "creditcard" => Some(PiiCategory::Identity),
        _ => None,
    }
}

fn iri_violates_pii(iri: &str, profile: &DisclosureProfile) -> bool {
    let lower = iri.to_ascii_lowercase();
    if lower.starts_with("mailto:") && !profile.allowed_categories.contains(&PiiCategory::Email) {
        return true;
    }
    if (lower.starts_with("tel:") || lower.starts_with("sms:"))
        && !profile.allowed_categories.contains(&PiiCategory::Phone)
    {
        return true;
    }
    if lower.starts_with("geo:") && !profile.allowed_categories.contains(&PiiCategory::Address) {
        return true;
    }
    false
}

fn rebuild_literal(original: &Literal, new_value: &str) -> Literal {
    if let Some(lang) = original.language() {
        Literal::new_language_tagged_literal(new_value, lang)
            .unwrap_or_else(|_| Literal::new_simple_literal(new_value))
    } else {
        Literal::new_typed_literal(new_value, original.datatype())
    }
}

/// Deterministic linear-time O(N) text scrubber (zero regex backtracking).
pub fn scrub_literal_text(input: &str, profile: &DisclosureProfile) -> String {
    let mut text = input.to_string();
    if profile.redact_secrets {
        text = scrub_secrets(&text);
    }
    if !profile.allowed_categories.contains(&PiiCategory::Email) {
        text = scrub_emails(&text);
    }
    if !profile.allowed_categories.contains(&PiiCategory::Identity) {
        text = scrub_identity_numbers(&text);
    }
    if !profile.allowed_categories.contains(&PiiCategory::Phone) {
        text = scrub_phone_numbers(&text);
    }
    text
}

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')
}

fn scrub_secrets(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while !rest.is_empty() {
        if let Some(after_open) = rest.strip_prefix("«redacted:") {
            if let Some(end_idx) = after_open.find('»') {
                out.push_str("[REDACTED_SECRET]");
                rest = &after_open[end_idx + '»'.len_utf8()..];
                continue;
            }
        }

        let matched_prefix = ["sk-", "ghp_", "gho_", "github_pat_"]
            .iter()
            .find(|&&p| rest.starts_with(p));
        if let Some(&prefix) = matched_prefix {
            let tail = &rest[prefix.len()..];
            let tok_len = tail.bytes().take_while(|&b| is_token_char(b)).count();
            if tok_len >= 8 {
                out.push_str("[REDACTED_SECRET]");
                rest = &tail[tok_len..];
                continue;
            }
        }

        let ch = rest.chars().next().unwrap();
        out.push(ch);
        rest = &rest[ch.len_utf8()..];
    }
    out
}

fn is_email_local_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_email_domain_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
}

fn scrub_emails(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut cursor = 0usize;
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'@' && i > cursor {
            let mut local_start = i;
            while local_start > cursor && is_email_local_byte(bytes[local_start - 1]) {
                local_start -= 1;
            }
            let mut dom_end = i + 1;
            while dom_end < bytes.len() && is_email_domain_byte(bytes[dom_end]) {
                dom_end += 1;
            }
            // Strip trailing punctuation `.` or `-`
            while dom_end > i + 1 && matches!(bytes[dom_end - 1], b'.' | b'-') {
                dom_end -= 1;
            }

            let local = &s[local_start..i];
            let domain = &s[i + 1..dom_end];
            let valid_domain = match domain.rsplit_once('.') {
                Some((host, tld)) => {
                    !host.is_empty()
                        && !host.starts_with('.')
                        && !host.contains("..")
                        && tld.len() >= 2
                        && tld.bytes().all(|b| b.is_ascii_alphabetic())
                }
                None => false,
            };

            if !local.is_empty() && !local.starts_with('.') && valid_domain {
                out.push_str(&s[cursor..local_start]);
                out.push_str("[REDACTED_EMAIL]");
                cursor = dom_end;
                i = dom_end;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&s[cursor..]);
    out
}

fn scrub_identity_numbers(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let prev_is_digit = i > 0 && bytes[i - 1].is_ascii_digit();
        if !prev_is_digit {
            // Korean Domestic & Foreign RRN: \d{6}-[1-8]\d{6} (14 bytes)
            if i + 14 <= bytes.len()
                && bytes[i..i + 6].iter().all(u8::is_ascii_digit)
                && bytes[i + 6] == b'-'
                && matches!(bytes[i + 7], b'1'..=b'8')
                && bytes[i + 8..i + 14].iter().all(u8::is_ascii_digit)
                && (i + 14 == bytes.len() || !bytes[i + 14].is_ascii_digit())
            {
                out.push_str("[REDACTED_PII]");
                i += 14;
                continue;
            }
            // US SSN: \d{3}-\d{2}-\d{4} (11 bytes)
            if i + 11 <= bytes.len()
                && bytes[i..i + 3].iter().all(u8::is_ascii_digit)
                && bytes[i + 3] == b'-'
                && bytes[i + 4..i + 6].iter().all(u8::is_ascii_digit)
                && bytes[i + 6] == b'-'
                && bytes[i + 7..i + 11].iter().all(u8::is_ascii_digit)
                && (i + 11 == bytes.len() || !bytes[i + 11].is_ascii_digit())
            {
                out.push_str("[REDACTED_PII]");
                i += 11;
                continue;
            }
        }

        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn match_phone_at(bytes: &[u8], start: usize) -> Option<usize> {
    if start > 0 && (bytes[start - 1].is_ascii_digit() || bytes[start - 1] == b'+') {
        return None;
    }

    let mut pos = start;
    // Optional `+<cc>-` international prefix (e.g. `+82-`)
    if bytes.get(pos) == Some(&b'+') {
        pos += 1;
        let cc_len = bytes[pos..]
            .iter()
            .take(3)
            .take_while(|b| b.is_ascii_digit())
            .count();
        if cc_len == 0 || bytes.get(pos + cc_len) != Some(&b'-') {
            return None;
        }
        pos += cc_len + 1;
    }

    // Area / carrier group: 2..=3 digits followed by '-'
    let g1 = bytes[pos..]
        .iter()
        .take(4)
        .take_while(|b| b.is_ascii_digit())
        .count();
    if !(2..=3).contains(&g1) || bytes.get(pos + g1) != Some(&b'-') {
        return None;
    }
    pos += g1 + 1;

    // Exchange group: 3..=4 digits followed by '-'
    let g2 = bytes[pos..]
        .iter()
        .take(5)
        .take_while(|b| b.is_ascii_digit())
        .count();
    if !(3..=4).contains(&g2) || bytes.get(pos + g2) != Some(&b'-') {
        return None;
    }
    pos += g2 + 1;

    // Subscriber group: exact 4 digits not followed by another digit
    let g3 = bytes[pos..]
        .iter()
        .take(5)
        .take_while(|b| b.is_ascii_digit())
        .count();
    if g3 != 4 {
        return None;
    }
    pos += 4;
    if pos < bytes.len() && bytes[pos].is_ascii_digit() {
        return None;
    }
    Some(pos)
}

fn scrub_phone_numbers(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if let Some(end) = match_phone_at(bytes, i) {
            out.push_str("[REDACTED_PHONE]");
            i = end;
            continue;
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_scrubber_preserves_iso_dates_and_scrubs_pii_and_secrets() {
        let profile = DisclosureProfile {
            zero_pii_enforced: true,
            redact_secrets: true,
            allowed_categories: BTreeSet::new(),
        };

        let sample = "Created 2026-11-13 by user@acme.io, tel 02-345-6789, SSN 123-45-6789, key ghp_AbCdEf123456";
        let out = scrub_literal_text(sample, &profile);
        assert!(
            out.contains("2026-11-13"),
            "ISO date must not be false-positived: {out}"
        );
        assert!(out.contains("[REDACTED_EMAIL]"));
        assert!(out.contains("[REDACTED_PHONE]"));
        assert!(out.contains("[REDACTED_PII]"));
        assert!(out.contains("[REDACTED_SECRET]"));
        assert!(!out.contains("user@acme.io"));
        assert!(!out.contains("02-345-6789"));
        assert!(!out.contains("123-45-6789"));
        assert!(!out.contains("ghp_AbCdEf123456"));
    }

    #[test]
    fn unit_custom_secret_pii_and_rdf_star_quoted_triples_redaction() {
        let mut policy = DisclosurePolicy::new();
        policy.register_pii_predicate(
            "https://corp.example/ns#employeeBadge",
            PiiCategory::Identity,
        );
        policy.register_secret_predicate("https://corp.example/ns#vaultPin");

        let agent = Principal::Agent {
            agent_id: "bot".to_string(),
            delegated_by: WebId("did:web:alice.wolin.id".to_string()),
            scope: vec!["read".to_string()],
        };
        let profile = DisclosureProfile::resolve(&agent, &policy);

        let subj = Subject::NamedNode(
            wolin_storage::rdf_model::NamedNode::new("https://corp.example/u/1").unwrap(),
        );
        let t_badge = Triple::new(
            subj.clone(),
            wolin_storage::rdf_model::NamedNode::new("https://corp.example/ns#employeeBadge")
                .unwrap(),
            Term::Literal(Literal::new_simple_literal("EMP-991")),
        );
        let t_pin = Triple::new(
            subj.clone(),
            wolin_storage::rdf_model::NamedNode::new("https://corp.example/ns#vaultPin").unwrap(),
            Term::Literal(Literal::new_simple_literal("0000")),
        );
        let quoted_subj = Triple::new(
            Subject::Triple(Box::new(t_pin.clone())),
            wolin_storage::rdf_model::NamedNode::new("https://corp.example/ns#source").unwrap(),
            Term::Literal(Literal::new_simple_literal("audit")),
        );
        let quoted_obj = Triple::new(
            subj,
            wolin_storage::rdf_model::NamedNode::new("https://corp.example/ns#asserts").unwrap(),
            Term::Triple(Box::new(t_badge.clone())),
        );

        let projected = project_triples(
            &[t_badge, t_pin, quoted_subj, quoted_obj],
            &profile,
            &policy,
        );
        assert!(projected.triples.is_empty());
        assert_eq!(projected.redacted_triples, 4);
    }
}
