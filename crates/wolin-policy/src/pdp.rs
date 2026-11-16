use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::warn;
use wolin_core::{Principal, ResourceUri, WebId};

const MAX_RESOURCE_URI_LEN: usize = 4096;

/// W3C WAC / ACP access modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessMode {
    Read,
    Write,
    Append,
    Control,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessDecision {
    Permit,
    Deny { reason: String },
}

impl AccessDecision {
    pub fn is_permit(&self) -> bool {
        matches!(self, Self::Permit)
    }
}

/// Subject matcher for WAC (`acl:agent`, `acl:agentClass`, `acl:origin`) and ACP (`acp:Matcher`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubjectMatcher {
    /// Matches a specific sovereign WebID or DID (`acl:agent`)
    WebId(WebId),
    /// Matches any authenticated human User or delegated Agent (`foaf:AuthenticatedAgent`)
    Authenticated,
    /// Matches anyone including `Principal::Anonymous` (`foaf:Agent`)
    Public,
    /// Matches federated enterprise identity issuer (`iss` or `did:web` origin)
    Issuer(String),
    /// Matches a specific AI Agent identifier (`agent_id`)
    AgentId(String),
}

/// W3C Web Access Control (`acl:Authorization`) rule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WacRule {
    pub id: String,
    /// Exact target resources (`acl:accessTo`)
    pub access_to: Vec<ResourceUri>,
    /// Inherited container prefixes (`acl:default`)
    pub default_for: Vec<ResourceUri>,
    pub subjects: Vec<SubjectMatcher>,
    pub modes: Vec<AccessMode>,
}

/// W3C Solid Access Control Policy (`acp:Policy` + `acp:Matcher`) with Deny-overrides
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcpPolicy {
    pub id: String,
    /// Exact target resources (`acp:accessControl`)
    pub targets: Vec<ResourceUri>,
    /// Inherited container prefixes (`acp:memberAccessControl`)
    pub inherited_containers: Vec<ResourceUri>,
    /// All matchers must match (`acp:allOf`)
    pub all_of: Vec<SubjectMatcher>,
    /// At least one matcher must match (`acp:anyOf`)
    pub any_of: Vec<SubjectMatcher>,
    /// None of these matchers may match (`acp:noneOf`)
    pub none_of: Vec<SubjectMatcher>,
    /// Allowed modes (`acp:allow`)
    pub allow: Vec<AccessMode>,
    /// Explicitly denied modes (`acp:deny` — always overrides allow)
    pub deny: Vec<AccessMode>,
}

/// Dynamic time- and scope-bounded AI Agent delegation grant
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationGrant {
    pub grant_id: String,
    pub agent_id: String,
    pub delegated_by: WebId,
    pub allowed_modes: Vec<AccessMode>,
    pub resource_scopes: Vec<ResourceUri>,
    pub expires_at: Option<i64>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PolicyEngine {
    wac_rules: Vec<WacRule>,
    acp_policies: Vec<AcpPolicy>,
    delegation_grants: Vec<DelegationGrant>,
    webid_issuers: HashMap<WebId, String>,
    require_explicit_delegation: bool,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_explicit_delegation_required(required: bool) -> Self {
        Self {
            require_explicit_delegation: required,
            ..Self::default()
        }
    }

    /// Bind a verified OIDC/DID issuer to a `WebId` so `SubjectMatcher::Issuer` policies
    /// apply identically when that user delegates to a `Principal::Agent`.
    pub fn bind_webid_issuer(&mut self, webid: WebId, issuer: impl Into<String>) {
        self.webid_issuers.insert(webid, issuer.into());
    }

    pub fn add_wac_rule(&mut self, rule: WacRule) {
        self.wac_rules.push(rule);
    }

    /// Remove all WAC rules whose `id` begins with `id_prefix`, returning the removed count.
    pub fn remove_wac_rules_by_prefix(&mut self, id_prefix: &str) -> usize {
        let before = self.wac_rules.len();
        self.wac_rules.retain(|r| !r.id.starts_with(id_prefix));
        before - self.wac_rules.len()
    }

    /// Purge all WAC rules, ACP policies, delegation grants, and WebID-issuer bindings
    /// associated with a retired Pod (`pod_resource_prefix` e.g. `"wolin://pod/pods/alice/"`).
    pub fn purge_pod_governance(
        &mut self,
        pod_resource_prefix: &str,
        acl_doc_prefix: &str,
        pod_webids: &[&str],
    ) {
        let bare_pod_uri = pod_resource_prefix.trim_end_matches('/');
        let matches_pod_uri =
            |u: &ResourceUri| u.0 == bare_pod_uri || u.0.starts_with(pod_resource_prefix);

        self.wac_rules.retain(|r| {
            !r.id.starts_with(acl_doc_prefix)
                && !r.access_to.iter().any(matches_pod_uri)
                && !r.default_for.iter().any(matches_pod_uri)
        });
        self.acp_policies.retain(|p| {
            !p.targets.iter().any(matches_pod_uri)
                && !p.inherited_containers.iter().any(matches_pod_uri)
        });
        self.delegation_grants.retain(|g| {
            !pod_webids.contains(&g.delegated_by.0.as_str())
                && !g.resource_scopes.iter().any(matches_pod_uri)
        });
        for webid in pod_webids {
            self.webid_issuers.remove(&WebId((*webid).to_string()));
        }
    }

    pub fn add_acp_policy(&mut self, policy: AcpPolicy) {
        if policy.all_of.is_empty() && policy.any_of.is_empty() {
            warn!(
                policy_id = %policy.id,
                "AcpPolicy added with empty all_of and any_of; ACP requires positive matchers to apply"
            );
        }
        self.acp_policies.push(policy);
    }

    pub fn add_delegation_grant(&mut self, grant: DelegationGrant) {
        self.delegation_grants.push(grant);
    }

    pub fn revoke_delegation(&mut self, grant_id: &str) -> bool {
        let mut found = false;
        for grant in &mut self.delegation_grants {
            if grant.grant_id == grant_id {
                grant.revoked = true;
                found = true;
            }
        }
        found
    }

    /// Remove revoked or expired delegation grants at `now_epoch_secs`, returning removed count.
    pub fn prune_expired_delegations(&mut self, now_epoch_secs: i64) -> usize {
        let before = self.delegation_grants.len();
        self.delegation_grants
            .retain(|g| !g.revoked && g.expires_at.is_none_or(|exp| now_epoch_secs < exp));
        before - self.delegation_grants.len()
    }

    /// Single-pod stateless scope & public-container evaluation.
    /// For multi-tenant pod isolation, WAC/ACP rules, and dynamic agent delegation lifecycles,
    /// evaluate against a configured `PolicyEngine` via [`PolicyEngine::evaluate_policy`].
    pub fn evaluate(
        principal: &Principal,
        target: &ResourceUri,
        mode: AccessMode,
    ) -> AccessDecision {
        let canonical_target = match canonicalize_resource_uri(&target.0) {
            Ok(s) => s,
            Err(reason) => return AccessDecision::Deny { reason },
        };

        match principal {
            Principal::User { webid, issuer } => {
                if webid.0.trim().is_empty() || issuer.trim().is_empty() {
                    return AccessDecision::Deny {
                        reason: "Invalid user principal: empty WebID or issuer".to_string(),
                    };
                }
                AccessDecision::Permit
            }
            Principal::Agent {
                agent_id,
                delegated_by,
                scope,
            } => {
                if agent_id.trim().is_empty() || delegated_by.0.trim().is_empty() {
                    return AccessDecision::Deny {
                        reason: "Invalid agent principal: empty agent_id or delegator".to_string(),
                    };
                }
                if agent_scope_allows(scope, &canonical_target, mode) {
                    AccessDecision::Permit
                } else {
                    AccessDecision::Deny {
                        reason: format!("Agent lacks scope: {}", canonical_scope_name(mode)),
                    }
                }
            }
            Principal::Anonymous => match mode {
                AccessMode::Read => {
                    if is_public_pod_container(&canonical_target) {
                        AccessDecision::Permit
                    } else {
                        AccessDecision::Deny {
                            reason: "Resource is private".to_string(),
                        }
                    }
                }
                _ => AccessDecision::Deny {
                    reason: "Authentication required for write/append/control".to_string(),
                },
            },
        }
    }

    /// Evaluate access against loaded WAC rules, ACP policies, and Dynamic Delegation grants
    /// using the current system clock.
    pub fn evaluate_policy(
        &self,
        principal: &Principal,
        target: &ResourceUri,
        mode: AccessMode,
    ) -> AccessDecision {
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(_) => {
                return AccessDecision::Deny {
                    reason: "System clock error: unable to verify policy timestamps".to_string(),
                };
            }
        };
        self.evaluate_policy_at(principal, target, mode, now)
    }

    /// Deterministic WAC / ACP + Dynamic Delegation evaluation at `now_epoch_secs`.
    pub fn evaluate_policy_at(
        &self,
        principal: &Principal,
        target: &ResourceUri,
        mode: AccessMode,
        now_epoch_secs: i64,
    ) -> AccessDecision {
        let canonical_target = match canonicalize_resource_uri(&target.0) {
            Ok(s) => s,
            Err(reason) => return AccessDecision::Deny { reason },
        };
        let target_str = canonical_target.as_str();

        match principal {
            Principal::Anonymous => {
                if mode == AccessMode::Control {
                    return AccessDecision::Deny {
                        reason: "Anonymous principal cannot hold Control access".to_string(),
                    };
                }
                let ctx = SubjectContext {
                    webid: None,
                    issuer: None,
                    agent_id: None,
                    authenticated: false,
                };
                if let Some(policy_id) = self.find_acp_deny(&ctx, target_str, mode) {
                    return AccessDecision::Deny {
                        reason: format!("Denied by ACP policy '{policy_id}'"),
                    };
                }
                if self.has_wac_or_acp_allow(&ctx, target_str, mode) {
                    AccessDecision::Permit
                } else {
                    AccessDecision::Deny {
                        reason: "No WAC/ACP rule grants anonymous access".to_string(),
                    }
                }
            }

            Principal::User { webid, issuer } => {
                if webid.0.trim().is_empty() || issuer.trim().is_empty() {
                    return AccessDecision::Deny {
                        reason: "Invalid user principal: empty WebID or issuer".to_string(),
                    };
                }
                let ctx = SubjectContext {
                    webid: Some(webid),
                    issuer: Some(issuer.as_str()),
                    agent_id: None,
                    authenticated: true,
                };
                if let Some(policy_id) = self.find_acp_deny(&ctx, target_str, mode) {
                    return AccessDecision::Deny {
                        reason: format!("Denied by ACP policy '{policy_id}'"),
                    };
                }
                if self.has_wac_or_acp_allow(&ctx, target_str, mode) {
                    AccessDecision::Permit
                } else {
                    AccessDecision::Deny {
                        reason: "No WAC/ACP rule permits user on target resource".to_string(),
                    }
                }
            }

            Principal::Agent {
                agent_id,
                delegated_by,
                scope,
            } => {
                if agent_id.trim().is_empty() || delegated_by.0.trim().is_empty() {
                    return AccessDecision::Deny {
                        reason: "Invalid agent principal: empty agent_id or delegator".to_string(),
                    };
                }

                // 1. Token scope enforcement
                if !agent_scope_allows(scope, target_str, mode) {
                    return AccessDecision::Deny {
                        reason: format!("Agent lacks scope: {}", canonical_scope_name(mode)),
                    };
                }

                // Resolve verified issuer for delegator (bound issuer or cryptographic DID method;
                // never split arbitrary HTTP WebIDs on `#` to prevent cross-IdP spoofing).
                let resolved_issuer = self
                    .webid_issuers
                    .get(delegated_by)
                    .cloned()
                    .or_else(|| infer_did_issuer(&delegated_by.0));

                // 2. Explicit ACP deny check against both Agent and Delegator
                let agent_ctx = SubjectContext {
                    webid: Some(delegated_by),
                    issuer: resolved_issuer.as_deref(),
                    agent_id: Some(agent_id.as_str()),
                    authenticated: true,
                };
                if let Some(policy_id) = self.find_acp_deny(&agent_ctx, target_str, mode) {
                    return AccessDecision::Deny {
                        reason: format!("Agent denied by ACP policy '{policy_id}'"),
                    };
                }

                // 3. Dynamic DelegationGrant lifecycle check (revocation, TTL, attenuated modes/resources)
                let matching_pair_grants: Vec<&DelegationGrant> = self
                    .delegation_grants
                    .iter()
                    .filter(|g| g.agent_id == *agent_id && g.delegated_by == *delegated_by)
                    .collect();

                if self.require_explicit_delegation || !matching_pair_grants.is_empty() {
                    if matching_pair_grants.is_empty() {
                        return AccessDecision::Deny {
                            reason: "Explicit delegation grant required for agent".to_string(),
                        };
                    }
                    let active_permitted = matching_pair_grants.iter().any(|grant| {
                        if grant.revoked {
                            return false;
                        }
                        if let Some(exp) = grant.expires_at
                            && now_epoch_secs >= exp
                        {
                            return false;
                        }
                        if !modes_satisfy(&grant.allowed_modes, mode, false) {
                            return false;
                        }
                        grant.resource_scopes.iter().any(|res| {
                            canonicalize_policy_pattern(&res.0).is_some_and(|pat| {
                                uri_matches_target_or_container(target_str, &pat)
                            })
                        })
                    });

                    if !active_permitted {
                        return AccessDecision::Deny {
                            reason: "No active, unrevoked delegation grant permits target and mode"
                                .to_string(),
                        };
                    }
                }

                // 4. Attenuation invariant: Agent cannot exceed delegator's WAC/ACP permissions
                let delegator_ctx = SubjectContext {
                    webid: Some(delegated_by),
                    issuer: resolved_issuer.as_deref(),
                    agent_id: None,
                    authenticated: true,
                };
                if let Some(policy_id) = self.find_acp_deny(&delegator_ctx, target_str, mode) {
                    return AccessDecision::Deny {
                        reason: format!("Delegator denied by ACP policy '{policy_id}'"),
                    };
                }
                if !self.has_wac_or_acp_allow(&delegator_ctx, target_str, mode) {
                    return AccessDecision::Deny {
                        reason: "Privilege escalation blocked: delegator lacks access to target"
                            .to_string(),
                    };
                }

                AccessDecision::Permit
            }
        }
    }

    fn find_acp_deny(
        &self,
        ctx: &SubjectContext<'_>,
        target: &str,
        mode: AccessMode,
    ) -> Option<&str> {
        for policy in &self.acp_policies {
            if !modes_deny(&policy.deny, mode) {
                continue;
            }
            if !acp_subject_matches(policy, ctx) {
                continue;
            }
            if acp_resource_matches_for_deny(policy, target) {
                return Some(policy.id.as_str());
            }
        }
        None
    }

    fn has_wac_or_acp_allow(
        &self,
        ctx: &SubjectContext<'_>,
        target: &str,
        mode: AccessMode,
    ) -> bool {
        // If `Write` is explicitly denied by ACP on `target`, a parent `Write` grant must NOT
        // implicitly satisfy `Append` — only an explicit `Append` grant can permit `Append`.
        let write_denied = mode == AccessMode::Append
            && self.find_acp_deny(ctx, target, AccessMode::Write).is_some();

        for rule in &self.wac_rules {
            if !wac_resource_matches(rule, target) {
                continue;
            }
            if !modes_satisfy(&rule.modes, mode, write_denied) {
                continue;
            }
            if rule.subjects.iter().any(|m| subject_matches(m, ctx)) {
                return true;
            }
        }

        for policy in &self.acp_policies {
            if !acp_resource_matches_for_allow(policy, target) {
                continue;
            }
            if !modes_satisfy(&policy.allow, mode, write_denied) {
                continue;
            }
            if acp_subject_matches(policy, ctx) {
                return true;
            }
        }

        false
    }
}

struct SubjectContext<'a> {
    webid: Option<&'a WebId>,
    issuer: Option<&'a str>,
    agent_id: Option<&'a str>,
    authenticated: bool,
}

fn subject_matches(matcher: &SubjectMatcher, ctx: &SubjectContext<'_>) -> bool {
    match matcher {
        SubjectMatcher::Public => true,
        SubjectMatcher::Authenticated => ctx.authenticated,
        SubjectMatcher::WebId(expected) => ctx.webid == Some(expected),
        SubjectMatcher::Issuer(expected_iss) => ctx.issuer == Some(expected_iss.as_str()),
        SubjectMatcher::AgentId(expected_agent) => ctx.agent_id == Some(expected_agent.as_str()),
    }
}

fn wac_resource_matches(rule: &WacRule, target: &str) -> bool {
    if rule
        .access_to
        .iter()
        .any(|u| canonicalize_policy_pattern(&u.0).is_some_and(|p| p == target))
    {
        return true;
    }
    rule.default_for.iter().any(|container| {
        canonicalize_policy_pattern(&container.0)
            .is_some_and(|pat| uri_matches_target_or_container(target, &pat))
    })
}

fn acp_resource_matches_for_allow(policy: &AcpPolicy, target: &str) -> bool {
    if policy
        .targets
        .iter()
        .any(|u| canonicalize_policy_pattern(&u.0).is_some_and(|p| p == target))
    {
        return true;
    }
    policy.inherited_containers.iter().any(|container| {
        canonicalize_policy_pattern(&container.0)
            .is_some_and(|pat| uri_matches_target_or_container(target, &pat))
    })
}

/// Fail-closed matcher for ACP `deny`: any unparseable pattern or root wildcard `"/"`
/// in a `deny` policy triggers a match rather than failing open silently.
fn acp_resource_matches_for_deny(policy: &AcpPolicy, target: &str) -> bool {
    for u in &policy.targets {
        match canonicalize_policy_pattern(&u.0) {
            Some(p) if p == "/" || p == target => return true,
            Some(_) => {}
            None => return true,
        }
    }
    for container in &policy.inherited_containers {
        match canonicalize_policy_pattern(&container.0) {
            Some(pat) if pat == "/" || uri_matches_target_or_container(target, &pat) => {
                return true;
            }
            Some(_) => {}
            None => return true,
        }
    }
    false
}

fn acp_subject_matches(policy: &AcpPolicy, ctx: &SubjectContext<'_>) -> bool {
    if policy.all_of.is_empty() && policy.any_of.is_empty() {
        return false;
    }
    if policy.none_of.iter().any(|m| subject_matches(m, ctx)) {
        return false;
    }
    if !policy.all_of.is_empty() && !policy.all_of.iter().all(|m| subject_matches(m, ctx)) {
        return false;
    }
    if !policy.any_of.is_empty() && !policy.any_of.iter().any(|m| subject_matches(m, ctx)) {
        return false;
    }
    true
}

fn modes_satisfy(granted: &[AccessMode], requested: AccessMode, write_denied: bool) -> bool {
    granted.contains(&requested)
        || (requested == AccessMode::Append
            && !write_denied
            && granted.contains(&AccessMode::Write))
}

fn modes_deny(denied: &[AccessMode], requested: AccessMode) -> bool {
    denied.contains(&requested)
        || (requested == AccessMode::Write && denied.contains(&AccessMode::Append))
}

fn canonical_scope_name(mode: AccessMode) -> &'static str {
    match mode {
        AccessMode::Read => "read",
        AccessMode::Append => "append",
        AccessMode::Write => "write",
        AccessMode::Control => "admin",
    }
}

fn scope_token_satisfies(token: &str, mode: AccessMode) -> bool {
    match mode {
        AccessMode::Read => matches!(token, "read" | "acl:Read"),
        AccessMode::Append => matches!(token, "append" | "write" | "acl:Append" | "acl:Write"),
        AccessMode::Write => matches!(token, "write" | "acl:Write"),
        AccessMode::Control => matches!(token, "control" | "admin" | "acl:Control"),
    }
}

fn agent_scope_allows(scopes: &[String], canonical_target: &str, mode: AccessMode) -> bool {
    for raw in scopes {
        let s = raw.trim();
        if s == "*" || scope_token_satisfies(s, mode) {
            return true;
        }
        if let Some((prefix_mode, resource_scope)) = s.split_once(':')
            && matches!(
                prefix_mode,
                "read" | "append" | "write" | "control" | "admin"
            )
            && scope_token_satisfies(prefix_mode, mode)
            && let Some(canonical_scope) = canonicalize_policy_pattern(resource_scope)
            && uri_matches_target_or_container(canonical_target, &canonical_scope)
        {
            return true;
        }
    }
    false
}

fn uri_matches_target_or_container(canonical_target: &str, canonical_container: &str) -> bool {
    if canonical_container.is_empty() {
        return false;
    }
    if canonical_container == "/" {
        return true;
    }
    canonical_target == canonical_container
        || (canonical_target.starts_with(canonical_container)
            && canonical_target.as_bytes().get(canonical_container.len()) == Some(&b'/'))
}

/// Only treat the top-level `public` container of a pod (`wolin://<pod>/public[/...]`)
/// as anonymously readable — never arbitrary leaf segments or query/fragment injections.
fn is_public_pod_container(canonical_target: &str) -> bool {
    let first_seg = match canonical_target.split_once("://") {
        Some((_, rest)) => match rest.split_once('/') {
            Some((_, path)) => path.split('/').next().unwrap_or_default(),
            None => return false,
        },
        None => canonical_target
            .trim_start_matches('/')
            .split('/')
            .next()
            .unwrap_or_default(),
    };
    first_seg == "public"
}

fn canonicalize_policy_pattern(raw: &str) -> Option<String> {
    if raw == "/" {
        return Some("/".to_string());
    }
    let trimmed = raw.trim_end_matches('/');
    canonicalize_resource_uri(trimmed).ok()
}

/// Strict RFC 3986 canonicalizer for resource URIs:
/// - Caps length at 4096 bytes before allocation
/// - Rejects `?` query strings, `#` fragments, `\` backslashes, whitespace, control bytes
/// - Rejects empty interior segments (`//`), `.` and `..`, and trailing `/` on leaf targets
/// - Decodes unreserved `%XX` bytes (`%73ecrets` -> `secrets`) and blocks encoded delimiters
fn canonicalize_resource_uri(s: &str) -> std::result::Result<String, String> {
    if s.is_empty() || s.len() > MAX_RESOURCE_URI_LEN {
        return Err("Invalid resource URI: empty or exceeds maximum length".to_string());
    }
    if s.bytes().any(|b| {
        b.is_ascii_control() || b.is_ascii_whitespace() || matches!(b, b'\\' | b'?' | b'#')
    }) {
        return Err(
            "Invalid resource URI: query, fragment, backslash, whitespace, or control byte rejected"
                .to_string(),
        );
    }

    let (scheme_prefix, authority_and_path) = match s.split_once("://") {
        Some((scheme, rest)) => {
            if scheme.is_empty()
                || !scheme
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
            {
                return Err("Invalid resource URI: malformed scheme".to_string());
            }
            if rest.is_empty() {
                return Err("Invalid resource URI: missing authority".to_string());
            }
            (Some(scheme.to_ascii_lowercase()), rest)
        }
        None => (None, s),
    };

    if authority_and_path.ends_with('/') {
        return Err("Invalid resource URI: trailing slash rejected on target URI".to_string());
    }

    let mut canonical = String::with_capacity(s.len());
    if let Some(scheme) = scheme_prefix {
        canonical.push_str(&scheme);
        canonical.push_str("://");
        let (authority, path_opt) = match authority_and_path.split_once('/') {
            Some((auth, p)) => (auth, Some(p)),
            None => (authority_and_path, None),
        };
        if authority.is_empty() || authority.contains('%') || authority.contains('@') {
            return Err(
                "Invalid resource URI: empty, userinfo-prefixed, or percent-encoded authority"
                    .to_string(),
            );
        }
        canonical.push_str(&authority.to_ascii_lowercase());
        if let Some(path) = path_opt {
            for seg in path.split('/') {
                if seg.is_empty() {
                    return Err(
                        "Invalid resource URI: empty '//' path segment rejected".to_string()
                    );
                }
                let clean_seg = decode_and_validate_uri_segment(seg)?;
                canonical.push('/');
                canonical.push_str(&clean_seg);
            }
        }
    } else {
        let leading_slash = authority_and_path.starts_with('/');
        let rel = authority_and_path.trim_start_matches('/');
        if rel.is_empty() || (leading_slash && authority_and_path.starts_with("//")) {
            return Err("Invalid resource URI: empty path".to_string());
        }
        for (idx, seg) in rel.split('/').enumerate() {
            if seg.is_empty() {
                return Err("Invalid resource URI: empty '//' path segment rejected".to_string());
            }
            let clean_seg = decode_and_validate_uri_segment(seg)?;
            if leading_slash || idx > 0 {
                canonical.push('/');
            }
            canonical.push_str(&clean_seg);
        }
    }

    Ok(canonical)
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

fn decode_and_validate_uri_segment(seg: &str) -> std::result::Result<String, String> {
    let bytes = seg.as_bytes();
    let mut decoded_bytes: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            if i + 2 >= bytes.len() {
                return Err("Invalid resource URI: truncated percent-encoding".to_string());
            }
            let hi = hex_nibble(bytes[i + 1])?;
            let lo = hex_nibble(bytes[i + 2])?;
            let decoded = (hi << 4) | lo;
            if matches!(
                decoded,
                b'/' | b'\\' | b'.' | b'?' | b'#' | 0x00..=0x20 | 0x7f
            ) {
                return Err(
                    "Invalid resource URI: encoded path delimiter, dot, or control byte rejected"
                        .to_string(),
                );
            }
            if b_is_unreserved_or_pchar_literal(decoded) || decoded >= 0x80 {
                decoded_bytes.push(decoded);
            } else {
                decoded_bytes.push(b'%');
                decoded_bytes.push(HEX_UPPER[hi as usize]);
                decoded_bytes.push(HEX_UPPER[lo as usize]);
            }
            i += 3;
        } else {
            decoded_bytes.push(b);
            i += 1;
        }
    }

    let out = String::from_utf8(decoded_bytes)
        .map_err(|_| "Invalid resource URI: non-UTF-8 byte sequence rejected".to_string())?;

    if out == "." || out == ".." {
        return Err("Invalid resource URI: path traversal segment rejected".to_string());
    }
    Ok(out)
}

/// RFC 3986 path-segment characters (`unreserved` + `:`, `@`) that normalize identically
/// whether supplied literally or percent-encoded (`%3A` -> `:`, `%40` -> `@`).
fn b_is_unreserved_or_pchar_literal(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b':' | b'@')
}

fn hex_nibble(b: u8) -> std::result::Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("Invalid resource URI: malformed hex percent-encoding".to_string()),
    }
}

/// Only infer self-certifying DID issuers from `WebId`; never split arbitrary HTTP WebIDs on `#`.
fn infer_did_issuer(webid: &str) -> Option<String> {
    if webid.starts_with("did:key:") {
        Some("did:key".to_string())
    } else if webid.starts_with("did:nostr:") {
        Some("did:nostr".to_string())
    } else if let Some(rest) = webid.strip_prefix("did:web:") {
        let host_seg = rest.split(':').next()?;
        if host_seg.is_empty() {
            return None;
        }
        let decoded_host = host_seg.to_ascii_lowercase().replace("%3a", ":");
        Some(format!("did:web:{decoded_host}"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wolin_core::WebId;

    #[test]
    fn test_user_access_permitted() {
        let user = Principal::User {
            webid: WebId("https://user.wolin.id/profile".to_string()),
            issuer: "wolin".to_string(),
        };
        let target = ResourceUri("wolin://pod/data/private".to_string());
        assert_eq!(
            PolicyEngine::evaluate(&user, &target, AccessMode::Read),
            AccessDecision::Permit
        );
        assert_eq!(
            PolicyEngine::evaluate(&user, &target, AccessMode::Write),
            AccessDecision::Permit
        );
    }

    #[test]
    fn test_agent_scope_enforcement() {
        let agent = Principal::Agent {
            agent_id: "claude-subagent-1".to_string(),
            delegated_by: WebId("https://user.wolin.id/profile".to_string()),
            scope: vec!["read".to_string()],
        };
        let target = ResourceUri("wolin://pod/data/doc".to_string());
        assert_eq!(
            PolicyEngine::evaluate(&agent, &target, AccessMode::Read),
            AccessDecision::Permit
        );
        assert!(matches!(
            PolicyEngine::evaluate(&agent, &target, AccessMode::Write),
            AccessDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_anonymous_public_only() {
        let anon = Principal::Anonymous;
        let pub_target = ResourceUri("wolin://pod/public/about".to_string());
        let priv_target = ResourceUri("wolin://pod/private/keys".to_string());

        assert_eq!(
            PolicyEngine::evaluate(&anon, &pub_target, AccessMode::Read),
            AccessDecision::Permit
        );
        assert!(matches!(
            PolicyEngine::evaluate(&anon, &priv_target, AccessMode::Read),
            AccessDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_anonymous_blocks_fragment_query_and_deep_public_leaf_bypass() {
        let anon = Principal::Anonymous;
        for bypass_attempt in [
            "wolin://pod/private/keys#/public",
            "wolin://pod/private/keys?x=/public/y",
            "wolin://pod/private/secrets/public",
            "wolin://pod//public/about",
        ] {
            assert!(
                !PolicyEngine::evaluate(
                    &anon,
                    &ResourceUri(bypass_attempt.to_string()),
                    AccessMode::Read
                )
                .is_permit(),
                "expected {bypass_attempt} to be denied for Anonymous"
            );
        }
    }

    #[test]
    fn test_acp_deny_cannot_be_bypassed_by_percent_encoding_double_slash_or_query() {
        let mut engine = PolicyEngine::new();
        let alice = Principal::User {
            webid: WebId("https://alice.acme.corp/profile#me".to_string()),
            issuer: "https://auth.zitadel.acme.corp".to_string(),
        };

        engine.add_wac_rule(WacRule {
            id: "allow-eng".to_string(),
            access_to: vec![],
            default_for: vec![ResourceUri("wolin://acme/eng/".to_string())],
            subjects: vec![SubjectMatcher::WebId(WebId(
                "https://alice.acme.corp/profile#me".to_string(),
            ))],
            modes: vec![AccessMode::Read, AccessMode::Write],
        });

        engine.add_acp_policy(AcpPolicy {
            id: "deny-secrets-and-roadmap".to_string(),
            targets: vec![ResourceUri("wolin://acme/eng/roadmap.md".to_string())],
            inherited_containers: vec![ResourceUri("wolin://acme/eng/secrets/".to_string())],
            all_of: vec![],
            any_of: vec![SubjectMatcher::Authenticated],
            none_of: vec![],
            allow: vec![],
            deny: vec![AccessMode::Write],
        });

        for attempt in [
            "wolin://acme/eng/%73ecrets/keys.json",
            "wolin://acme/eng//secrets/keys.json",
            "wolin://acme/eng/roadmap.md?raw=1",
            "wolin://acme/eng/roadmap.md#v1",
            "wolin://acme/eng/roadmap.md/",
        ] {
            assert!(
                !engine
                    .evaluate_policy_at(
                        &alice,
                        &ResourceUri(attempt.to_string()),
                        AccessMode::Write,
                        1_763_000_000
                    )
                    .is_permit(),
                "expected Write on {attempt} to be denied"
            );
            // Also verify Write-deny blocks implicit Append inheritance from parent Write rule!
            assert!(
                !engine
                    .evaluate_policy_at(
                        &alice,
                        &ResourceUri(attempt.to_string()),
                        AccessMode::Append,
                        1_763_000_000
                    )
                    .is_permit(),
                "expected implicit Append via parent Write on {attempt} to be denied"
            );
        }
    }

    #[test]
    fn test_bound_issuer_acp_deny_enforced_on_delegated_agent_and_grant_pruning() {
        let mut engine = PolicyEngine::new();
        let alice_id = WebId("https://alice.acme.corp/profile#me".to_string());
        engine.bind_webid_issuer(alice_id.clone(), "https://auth.zitadel.acme.corp");

        engine.add_wac_rule(WacRule {
            id: "allow-alice".to_string(),
            access_to: vec![ResourceUri("wolin://acme/doc.ttl".to_string())],
            default_for: vec![],
            subjects: vec![SubjectMatcher::WebId(alice_id.clone())],
            modes: vec![AccessMode::Read],
        });

        engine.add_acp_policy(AcpPolicy {
            id: "deny-idp-maintenance".to_string(),
            targets: vec![ResourceUri("wolin://acme/doc.ttl".to_string())],
            inherited_containers: vec![],
            all_of: vec![],
            any_of: vec![SubjectMatcher::Issuer(
                "https://auth.zitadel.acme.corp".to_string(),
            )],
            none_of: vec![],
            allow: vec![],
            deny: vec![AccessMode::Read],
        });

        let agent = Principal::Agent {
            agent_id: "bot-1".to_string(),
            delegated_by: alice_id.clone(),
            scope: vec!["read".to_string()],
        };
        assert!(
            !engine
                .evaluate_policy_at(
                    &agent,
                    &ResourceUri("wolin://acme/doc.ttl".to_string()),
                    AccessMode::Read,
                    1000
                )
                .is_permit()
        );

        engine.add_delegation_grant(DelegationGrant {
            grant_id: "g-exp".to_string(),
            agent_id: "bot-1".to_string(),
            delegated_by: alice_id,
            allowed_modes: vec![AccessMode::Read],
            resource_scopes: vec![ResourceUri("wolin://acme/".to_string())],
            expires_at: Some(500),
            revoked: false,
        });
        assert_eq!(engine.prune_expired_delegations(1000), 1);
    }

    #[test]
    fn test_resource_qualified_agent_scope() {
        let agent = Principal::Agent {
            agent_id: "scoped-agent".to_string(),
            delegated_by: WebId("https://alice.wolin.id/profile".to_string()),
            scope: vec!["read:wolin://pod/projects/alpha".to_string()],
        };
        let allowed = ResourceUri("wolin://pod/projects/alpha/roadmap.md".to_string());
        let blocked = ResourceUri("wolin://pod/projects/alpha_secret/roadmap.md".to_string());

        assert!(PolicyEngine::evaluate(&agent, &allowed, AccessMode::Read).is_permit());
        assert!(!PolicyEngine::evaluate(&agent, &blocked, AccessMode::Read).is_permit());
    }

    #[test]
    fn test_acp_all_of_and_none_of_matchers() {
        let mut engine = PolicyEngine::new();
        let alice = Principal::User {
            webid: WebId("https://alice.corp/id".to_string()),
            issuer: "https://sso.corp".to_string(),
        };
        let contractor = Principal::User {
            webid: WebId("https://contractor.corp/id".to_string()),
            issuer: "https://sso.corp".to_string(),
        };

        engine.add_acp_policy(AcpPolicy {
            id: "corp-employees-except-contractor".to_string(),
            targets: vec![ResourceUri("wolin://corp/board/minutes.ttl".to_string())],
            inherited_containers: vec![],
            all_of: vec![
                SubjectMatcher::Authenticated,
                SubjectMatcher::Issuer("https://sso.corp".to_string()),
            ],
            any_of: vec![],
            none_of: vec![SubjectMatcher::WebId(WebId(
                "https://contractor.corp/id".to_string(),
            ))],
            allow: vec![AccessMode::Read],
            deny: vec![],
        });

        let target = ResourceUri("wolin://corp/board/minutes.ttl".to_string());
        assert_eq!(
            engine.evaluate_policy_at(&alice, &target, AccessMode::Read, 1_700_000_000),
            AccessDecision::Permit
        );
        assert!(matches!(
            engine.evaluate_policy_at(&contractor, &target, AccessMode::Read, 1_700_000_000),
            AccessDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_utf8_percent_encoding_colon_normalization_and_fail_closed_acp_deny() {
        let mut engine = PolicyEngine::new();
        let alice = Principal::User {
            webid: WebId("https://alice.corp/id".to_string()),
            issuer: "https://sso.corp".to_string(),
        };

        engine.add_wac_rule(WacRule {
            id: "allow-corp".to_string(),
            access_to: vec![],
            default_for: vec![ResourceUri("wolin://corp/문서".to_string())],
            subjects: vec![SubjectMatcher::Authenticated],
            modes: vec![AccessMode::Read],
        });

        engine.add_acp_policy(AcpPolicy {
            id: "deny-secret-korean-and-colon".to_string(),
            targets: vec![ResourceUri("wolin://corp/문서/기밀:v1.ttl".to_string())],
            inherited_containers: vec![],
            all_of: vec![],
            any_of: vec![SubjectMatcher::Authenticated],
            none_of: vec![],
            allow: vec![],
            deny: vec![AccessMode::Read],
        });

        // Percent-encoded UTF-8 (`문서`/`기밀`) + `%3a` must canonicalize identically and hit ACP deny
        let encoded_attempt =
            ResourceUri("wolin://corp/%EB%AC%B8%EC%84%9C/%EA%B8%B0%EB%B0%80%3av1.ttl".to_string());
        assert!(
            !engine
                .evaluate_policy_at(&alice, &encoded_attempt, AccessMode::Read, 1000)
                .is_permit()
        );

        // Malformed pattern in ACP deny must fail closed (block rather than skip)
        let mut bad_deny_engine = PolicyEngine::new();
        bad_deny_engine.add_wac_rule(WacRule {
            id: "allow-all".to_string(),
            access_to: vec![],
            default_for: vec![ResourceUri("/".to_string())],
            subjects: vec![SubjectMatcher::Authenticated],
            modes: vec![AccessMode::Read],
        });
        bad_deny_engine.add_acp_policy(AcpPolicy {
            id: "malformed-deny-pattern".to_string(),
            targets: vec![ResourceUri("".to_string())],
            inherited_containers: vec![],
            all_of: vec![],
            any_of: vec![SubjectMatcher::Authenticated],
            none_of: vec![],
            allow: vec![],
            deny: vec![AccessMode::Read],
        });
        assert!(
            !bad_deny_engine
                .evaluate_policy_at(
                    &alice,
                    &ResourceUri("wolin://corp/any.ttl".to_string()),
                    AccessMode::Read,
                    1000
                )
                .is_permit()
        );
    }
}
