use rand::Rng;
use uuid::Uuid;

pub use crate::types::{Canary, SecretType};

/// Generates format-valid honeypot credentials that look real to an LLM
/// but are uniquely identifiable by our monitoring layer.
pub struct CanaryGenerator;

impl CanaryGenerator {
    /// Generate a full suite of canary credentials for one detonation.
    /// Each value is random but structurally matches the real format
    /// so that an LLM (or prompt injection payload) treats it as genuine.
    pub fn generate(count: usize) -> Vec<Canary> {
        let mut rng = rand::thread_rng();
        let mut canaries = Vec::new();

        // We always generate at least the core set, up to `count`
        let types: Vec<SecretType> = vec![
            SecretType::AwsAccessKey,
            SecretType::AwsSecretKey,
            SecretType::StripeKey,
            SecretType::GithubPat,
            SecretType::DatabaseUrl,
            SecretType::EthWallet,
            SecretType::SshPrivateKey,
            SecretType::SlackWebhook,
            SecretType::GenericApiKey,
        ];

        for secret_type in types.iter().take(count) {
            let value = match secret_type {
                SecretType::AwsAccessKey => Self::aws_access_key(&mut rng),
                SecretType::AwsSecretKey => Self::aws_secret_key(&mut rng),
                SecretType::StripeKey => Self::stripe_key(&mut rng),
                SecretType::GithubPat => Self::github_pat(&mut rng),
                SecretType::DatabaseUrl => Self::database_url(&mut rng),
                SecretType::EthWallet => Self::eth_wallet(&mut rng),
                SecretType::SshPrivateKey => Self::ssh_private_key(&mut rng),
                SecretType::SlackWebhook => Self::slack_webhook(&mut rng),
                SecretType::GenericApiKey => Self::generic_api_key(&mut rng),
            };

            canaries.push(Canary {
                id: Uuid::new_v4(),
                secret_type: secret_type.clone(),
                value,
                label: secret_type.label().to_string(),
            });
        }

        canaries
    }

    // ── Format-valid credential generators ────────────────────────────

    /// AWS Access Key ID: AKIA + 16 uppercase alphanumeric = 20 chars
    fn aws_access_key(rng: &mut impl Rng) -> String {
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let suffix: String = (0..16)
            .map(|_| chars[rng.gen_range(0..chars.len())] as char)
            .collect();
        format!("AKIA{}", suffix)
    }

    /// AWS Secret Access Key: 40 chars from [A-Za-z0-9/+=]
    fn aws_secret_key(rng: &mut impl Rng) -> String {
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+=";
        (0..40)
            .map(|_| chars[rng.gen_range(0..chars.len())] as char)
            .collect()
    }

    /// Stripe Secret Key: sk_live_ + 24 alphanumeric
    fn stripe_key(rng: &mut impl Rng) -> String {
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let body: String = (0..24)
            .map(|_| chars[rng.gen_range(0..chars.len())] as char)
            .collect();
        format!("sk_live_{}", body)
    }

    /// GitHub Personal Access Token: ghp_ + 36 alphanumeric
    fn github_pat(rng: &mut impl Rng) -> String {
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let body: String = (0..36)
            .map(|_| chars[rng.gen_range(0..chars.len())] as char)
            .collect();
        format!("ghp_{}", body)
    }

    /// PostgreSQL connection string
    fn database_url(rng: &mut impl Rng) -> String {
        let pass_chars = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let password: String = (0..16)
            .map(|_| pass_chars[rng.gen_range(0..pass_chars.len())] as char)
            .collect();
        let db_chars = b"abcdefghijklmnopqrstuvwxyz";
        let db: String = (0..8)
            .map(|_| db_chars[rng.gen_range(0..db_chars.len())] as char)
            .collect();
        format!(
            "postgresql://dbadmin:{}@prod-db.internal:5432/{}",
            password, db
        )
    }

    /// Ethereum private key: 64 hex chars
    fn eth_wallet(rng: &mut impl Rng) -> String {
        let hex = b"0123456789abcdef";
        let key: String = (0..64)
            .map(|_| hex[rng.gen_range(0..hex.len())] as char)
            .collect();
        format!("0x{}", key)
    }

    /// Fake but realistic-looking Ed25519 SSH private key (PEM-encoded)
    fn ssh_private_key(rng: &mut impl Rng) -> String {
        let bytes: Vec<u8> = (0..256).map(|_| rng.gen::<u8>()).collect();
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
        let mut wrapped = String::new();
        for chunk in encoded.as_bytes().chunks(70) {
            wrapped.push_str(std::str::from_utf8(chunk).unwrap());
            wrapped.push('\n');
        }
        format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}-----END OPENSSH PRIVATE KEY-----",
            wrapped
        )
    }

    /// Slack webhook URL: https://hooks.slack.com/services/T.../B.../xxx
    fn slack_webhook(rng: &mut impl Rng) -> String {
        let alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let alnum = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        let team: String = (0..8)
            .map(|_| alpha[rng.gen_range(0..alpha.len())] as char)
            .collect();
        let channel: String = (0..8)
            .map(|_| alpha[rng.gen_range(0..alpha.len())] as char)
            .collect();
        let token: String = (0..24)
            .map(|_| alnum[rng.gen_range(0..alnum.len())] as char)
            .collect();

        format!(
            "https://hooks.slack.com/services/T{}/B{}/{}",
            team, channel, token
        )
    }

    /// Generic API key: 32 hex chars with a realistic prefix
    fn generic_api_key(rng: &mut impl Rng) -> String {
        let hex = b"0123456789abcdef";
        let body: String = (0..32)
            .map(|_| hex[rng.gen_range(0..hex.len())] as char)
            .collect();
        format!("dsk_prod_{}", body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_requested_count() {
        let canaries = CanaryGenerator::generate(5);
        assert_eq!(canaries.len(), 5);
    }

    #[test]
    fn aws_key_format_valid() {
        let mut rng = rand::thread_rng();
        let key = CanaryGenerator::aws_access_key(&mut rng);
        assert!(key.starts_with("AKIA"));
        assert_eq!(key.len(), 20);
    }

    #[test]
    fn stripe_key_format_valid() {
        let mut rng = rand::thread_rng();
        let key = CanaryGenerator::stripe_key(&mut rng);
        assert!(key.starts_with("sk_live_"));
    }

    #[test]
    fn github_pat_format_valid() {
        let mut rng = rand::thread_rng();
        let pat = CanaryGenerator::github_pat(&mut rng);
        assert!(pat.starts_with("ghp_"));
    }

    #[test]
    fn eth_wallet_format_valid() {
        let mut rng = rand::thread_rng();
        let wallet = CanaryGenerator::eth_wallet(&mut rng);
        assert!(wallet.starts_with("0x"));
        assert_eq!(wallet.len(), 66); // 0x + 64 hex
    }

    #[test]
    fn ssh_key_has_pem_headers() {
        let mut rng = rand::thread_rng();
        let key = CanaryGenerator::ssh_private_key(&mut rng);
        assert!(key.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(key.contains("END OPENSSH PRIVATE KEY"));
    }

    #[test]
    fn each_canary_gets_unique_id() {
        let canaries = CanaryGenerator::generate(8);
        let ids: std::collections::HashSet<_> = canaries.iter().map(|c| c.id).collect();
        assert_eq!(ids.len(), 8);
    }
}