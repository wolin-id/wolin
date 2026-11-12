use serde_json::json;
use wolin_core::{Principal, ResourceUri, WebId};
use wolin_identity::{DidResolver, OidcValidationOptions, OidcValidator};
use wolin_policy::{
    AccessDecision, AccessMode, AcpPolicy, DelegationGrant, PolicyEngine, SubjectMatcher, WacRule,
};

#[test]
fn stateless_pdp_append_control_and_traversal_defense() {
    let append_agent = Principal::Agent {
        agent_id: "inbox-bot".to_string(),
        delegated_by: WebId("https://alice.wolin.id/profile#me".to_string()),
        scope: vec!["append".to_string()],
    };
    let inbox = ResourceUri("wolin://alice/inbox/notification-1".to_string());

    // `append` scope permits Append, but MUST NOT permit full Write, Read, or Control
    assert_eq!(
        PolicyEngine::evaluate(&append_agent, &inbox, AccessMode::Append),
        AccessDecision::Permit
    );
    assert!(matches!(
        PolicyEngine::evaluate(&append_agent, &inbox, AccessMode::Write),
        AccessDecision::Deny { .. }
    ));
    assert!(matches!(
        PolicyEngine::evaluate(&append_agent, &inbox, AccessMode::Read),
        AccessDecision::Deny { .. }
    ));
    assert!(matches!(
        PolicyEngine::evaluate(&append_agent, &inbox, AccessMode::Control),
        AccessDecision::Deny { .. }
    ));

    // `write` scope implies both Write and Append in WAC, but NOT Control
    let write_agent = Principal::Agent {
        agent_id: "editor-bot".to_string(),
        delegated_by: WebId("https://alice.wolin.id/profile#me".to_string()),
        scope: vec!["write".to_string()],
    };
    assert_eq!(
        PolicyEngine::evaluate(&write_agent, &inbox, AccessMode::Write),
        AccessDecision::Permit
    );
    assert_eq!(
        PolicyEngine::evaluate(&write_agent, &inbox, AccessMode::Append),
        AccessDecision::Permit
    );
    assert!(matches!(
        PolicyEngine::evaluate(&write_agent, &inbox, AccessMode::Control),
        AccessDecision::Deny { .. }
    ));

    // Path traversal inside `/public/` MUST be denied even for Anonymous Read
    let traversal = ResourceUri("wolin://alice/public/../../private/keys".to_string());
    assert!(matches!(
        PolicyEngine::evaluate(&Principal::Anonymous, &traversal, AccessMode::Read),
        AccessDecision::Deny { .. }
    ));
}

#[test]
fn wac_container_inheritance_and_segment_boundary_safety() {
    let mut engine = PolicyEngine::new();
    let alice_id = WebId("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string()); // gitleaks:allow
    let bob_id = WebId(
        "did:nostr:7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"
            .to_string(),
    );

    engine.add_wac_rule(WacRule {
        id: "alice-pod-owner".to_string(),
        access_to: vec![],
        default_for: vec![ResourceUri("wolin://alice/docs".to_string())],
        subjects: vec![SubjectMatcher::WebId(alice_id.clone())],
        modes: vec![AccessMode::Read, AccessMode::Write, AccessMode::Control],
    });

    engine.add_wac_rule(WacRule {
        id: "public-inbox-append".to_string(),
        access_to: vec![ResourceUri("wolin://alice/inbox".to_string())],
        default_for: vec![],
        subjects: vec![SubjectMatcher::Public],
        modes: vec![AccessMode::Append],
    });

    let alice = DidResolver::resolve_principal(&alice_id.0).expect("alice principal");
    let bob = DidResolver::resolve_principal(&bob_id.0).expect("bob principal");

    // Alice inherits Read, Write, Append (via Write), and Control under wolin://alice/docs/...
    let report = ResourceUri("wolin://alice/docs/2026/q4.ttl".to_string());
    assert_eq!(
        engine.evaluate_policy(&alice, &report, AccessMode::Read),
        AccessDecision::Permit
    );
    assert_eq!(
        engine.evaluate_policy(&alice, &report, AccessMode::Append),
        AccessDecision::Permit
    );
    assert_eq!(
        engine.evaluate_policy(&alice, &report, AccessMode::Control),
        AccessDecision::Permit
    );

    // Segment boundary check: `wolin://alice/docs_secret/file` MUST NOT match `wolin://alice/docs`
    let sibling_collision = ResourceUri("wolin://alice/docs_secret/file.ttl".to_string());
    assert!(matches!(
        engine.evaluate_policy(&alice, &sibling_collision, AccessMode::Read),
        AccessDecision::Deny { .. }
    ));

    // Bob is denied on Alice's private docs
    assert!(matches!(
        engine.evaluate_policy(&bob, &report, AccessMode::Read),
        AccessDecision::Deny { .. }
    ));

    // Anonymous can Append to inbox via WAC Public rule, but cannot Read or Write it
    let inbox = ResourceUri("wolin://alice/inbox".to_string());
    assert_eq!(
        engine.evaluate_policy(&Principal::Anonymous, &inbox, AccessMode::Append),
        AccessDecision::Permit
    );
    assert!(matches!(
        engine.evaluate_policy(&Principal::Anonymous, &inbox, AccessMode::Read),
        AccessDecision::Deny { .. }
    ));
}

#[test]
fn acp_deny_overrides_and_dynamic_agent_delegation_lifecycle() {
    let now = 1_763_000_000_i64;
    let mut engine = PolicyEngine::with_explicit_delegation_required(true);

    let alice_webid = WebId("https://alice.acme.corp/profile#me".to_string());
    let bob_webid = WebId("https://bob.acme.corp/profile#me".to_string());

    // Enterprise IdP federated read access to shared engineering container
    engine.add_wac_rule(WacRule {
        id: "acme-eng-shared".to_string(),
        access_to: vec![],
        default_for: vec![ResourceUri("wolin://acme/eng/".to_string())],
        subjects: vec![SubjectMatcher::Issuer(
            "https://auth.zitadel.acme.corp".to_string(),
        )],
        modes: vec![AccessMode::Read, AccessMode::Write],
    });

    // ACP policy: explicitly deny AI agent access to `wolin://acme/eng/secrets/`
    engine.add_acp_policy(AcpPolicy {
        id: "block-agents-from-secrets".to_string(),
        targets: vec![],
        inherited_containers: vec![ResourceUri("wolin://acme/eng/secrets/".to_string())],
        all_of: vec![],
        any_of: vec![SubjectMatcher::AgentId(
            "did:web:acme.corp:agents:Summarizer".to_string(),
        )],
        none_of: vec![],
        allow: vec![],
        deny: vec![AccessMode::Read, AccessMode::Write, AccessMode::Append],
    });

    // Bob's private vault (Alice does NOT have access)
    engine.add_wac_rule(WacRule {
        id: "bob-vault".to_string(),
        access_to: vec![],
        default_for: vec![ResourceUri("wolin://bob/vault/".to_string())],
        subjects: vec![SubjectMatcher::WebId(bob_webid)],
        modes: vec![AccessMode::Read, AccessMode::Write, AccessMode::Control],
    });

    // Build delegated OIDC JWT for Alice's Summarizer agent
    let b64 = |b: &[u8]| {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut s = String::new();
        let mut i = 0;
        while i + 3 <= b.len() {
            let n = ((b[i] as u32) << 16) | ((b[i + 1] as u32) << 8) | (b[i + 2] as u32);
            s.push(T[((n >> 18) & 63) as usize] as char);
            s.push(T[((n >> 12) & 63) as usize] as char);
            s.push(T[((n >> 6) & 63) as usize] as char);
            s.push(T[(n & 63) as usize] as char);
            i += 3;
        }
        let r = b.len() - i;
        if r == 1 {
            let n = (b[i] as u32) << 16;
            s.push(T[((n >> 18) & 63) as usize] as char);
            s.push(T[((n >> 12) & 63) as usize] as char);
        } else if r == 2 {
            let n = ((b[i] as u32) << 16) | ((b[i + 1] as u32) << 8);
            s.push(T[((n >> 18) & 63) as usize] as char);
            s.push(T[((n >> 12) & 63) as usize] as char);
            s.push(T[((n >> 6) & 63) as usize] as char);
        }
        s
    };

    let jwt = format!(
        "{}.{}.{}",
        b64(json!({"alg": "EdDSA"}).to_string().as_bytes()),
        b64(json!({
            "iss": "https://auth.zitadel.acme.corp",
            "sub": "alice-uid",
            "webid": alice_webid.0,
            "aud": "wolin-gateway",
            "exp": now + 600,
            "scope": "read write",
            "act": { "sub": "did:web:acme.corp:agents:Summarizer" }
        })
        .to_string()
        .as_bytes()),
        b64(b"sig-ok")
    );

    let agent = OidcValidator::validate_with_options(
        &jwt,
        &OidcValidationOptions::new("https://auth.zitadel.acme.corp")
            .with_audience("wolin-gateway")
            .with_now(now),
    )
    .expect("valid delegated agent");

    // Also grant Alice WebID direct WAC rule on `wolin://acme/eng/` so her WebId is authorized
    engine.add_wac_rule(WacRule {
        id: "alice-eng-access".to_string(),
        access_to: vec![],
        default_for: vec![ResourceUri("wolin://acme/eng/".to_string())],
        subjects: vec![SubjectMatcher::WebId(alice_webid.clone())],
        modes: vec![AccessMode::Read, AccessMode::Write],
    });

    let spec_doc = ResourceUri("wolin://acme/eng/architecture.md".to_string());
    let secret_doc = ResourceUri("wolin://acme/eng/secrets/keys.json".to_string());
    let bob_doc = ResourceUri("wolin://bob/vault/tax.pdf".to_string());

    // Before DelegationGrant is registered -> Denied (explicit delegation required)
    assert!(matches!(
        engine.evaluate_policy_at(&agent, &spec_doc, AccessMode::Read, now),
        AccessDecision::Deny { .. }
    ));

    // Register time-bounded, read-only DelegationGrant for wolin://acme/eng/
    engine.add_delegation_grant(DelegationGrant {
        grant_id: "grant-001".to_string(),
        agent_id: "did:web:acme.corp:agents:Summarizer".to_string(),
        delegated_by: alice_webid,
        allowed_modes: vec![AccessMode::Read],
        resource_scopes: vec![ResourceUri("wolin://acme/eng/".to_string())],
        expires_at: Some(now + 120),
        revoked: false,
    });

    // 1. Permitted on `wolin://acme/eng/architecture.md` for Read
    assert_eq!(
        engine.evaluate_policy_at(&agent, &spec_doc, AccessMode::Read, now),
        AccessDecision::Permit
    );

    // 2. Denied for Write because DelegationGrant attenuated mode to Read only (even though JWT had `write` scope!)
    assert!(matches!(
        engine.evaluate_policy_at(&agent, &spec_doc, AccessMode::Write, now),
        AccessDecision::Deny { .. }
    ));

    // 3. Denied on `wolin://acme/eng/secrets/keys.json` due to ACP explicit Deny override!
    assert!(matches!(
        engine.evaluate_policy_at(&agent, &secret_doc, AccessMode::Read, now),
        AccessDecision::Deny { .. }
    ));

    // 4. Denied on Bob's vault even if grant were broader (delegator privilege escalation check)
    assert!(matches!(
        engine.evaluate_policy_at(&agent, &bob_doc, AccessMode::Read, now),
        AccessDecision::Deny { .. }
    ));

    // 5. Denied after TTL expiration (`now + 120`)
    assert!(matches!(
        engine.evaluate_policy_at(&agent, &spec_doc, AccessMode::Read, now + 120),
        AccessDecision::Deny { .. }
    ));

    // 6. Denied immediately when revoked before expiration
    assert!(engine.revoke_delegation("grant-001"));
    assert!(matches!(
        engine.evaluate_policy_at(&agent, &spec_doc, AccessMode::Read, now + 10),
        AccessDecision::Deny { .. }
    ));
}
