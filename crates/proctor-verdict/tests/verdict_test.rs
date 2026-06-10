use proctor_verdict::sign::Signer;
use proctor_verdict::verdict::{Status, Verdict, VerdictBuilder};

fn sample(signer: &Signer) -> Verdict {
    VerdictBuilder {
        task_id: "demo".into(),
        pass: false,
        status: Status::Compromised,
        violations_head: "abc123".into(),
        violations_count: 3,
        env_digest: "deadbeef".into(),
        reward: Some(0.0),
    }
    .sign(signer)
}

#[test]
fn signed_verdict_verifies() {
    let signer = Signer::generate();
    let v = sample(&signer);
    assert!(v.verify(&signer.public_key_hex()).is_ok());
}

#[test]
fn tampered_field_fails_verification() {
    let signer = Signer::generate();
    let mut v = sample(&signer);
    v.body.pass = true; // flip the result
    assert!(v.verify(&signer.public_key_hex()).is_err());
}

#[test]
fn tampered_violation_count_fails_verification() {
    let signer = Signer::generate();
    let mut v = sample(&signer);
    v.body.violations_count = 0; // hide the cheating
    assert!(v.verify(&signer.public_key_hex()).is_err());
}

#[test]
fn wrong_key_fails_verification() {
    let signer = Signer::generate();
    let other = Signer::generate();
    let v = sample(&signer);
    assert!(v.verify(&other.public_key_hex()).is_err());
}

#[test]
fn round_trips_through_json() {
    let signer = Signer::generate();
    let v = sample(&signer);
    let j = serde_json::to_string_pretty(&v).unwrap();
    let back: Verdict = serde_json::from_str(&j).unwrap();
    assert_eq!(back, v);
    assert!(back.verify(&signer.public_key_hex()).is_ok());
}

#[test]
fn seed_round_trip_reproduces_key() {
    let s = Signer::generate();
    let seed = s.to_seed_hex();
    let seed_bytes: [u8; 32] = hex::decode(&seed).unwrap().try_into().unwrap();
    let s2 = Signer::from_bytes(&seed_bytes);
    assert_eq!(s.public_key_hex(), s2.public_key_hex());
}
