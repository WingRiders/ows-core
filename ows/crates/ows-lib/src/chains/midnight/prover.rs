use super::error::PayError;
use midnight_base_crypto::data_provider::{self, MidnightDataProvider};
use midnight_base_crypto::rng::SplittableRng as _;
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use transient_crypto::curve::Fr;
use transient_crypto::proofs::{
    KeyLocation, Proof, ProofPreimage, ProvingKeyMaterial, ProvingProvider, Resolver,
};
use zkir_v2::LocalProvingProvider;

#[derive(Clone)]
pub struct OwsProver {
    rng: StdRng,
    provider: MidnightDataProvider,
}

struct OwsResolver(MidnightDataProvider);

impl Resolver for OwsResolver {
    async fn resolve_key(&self, key: KeyLocation) -> std::io::Result<Option<ProvingKeyMaterial>> {
        let file_root: String = match &*key.0 {
            "midnight/dust/spend" => format!("dust/{}/spend", midnight_ledger_static::version!()),
            "midnight/zswap/spend" => format!("zswap/{}/spend", midnight_ledger_static::version!()),
            "midnight/zswap/output" => {
                format!("zswap/{}/output", midnight_ledger_static::version!())
            }
            "midnight/zswap/sign" => format!("zswap/{}/sign", midnight_ledger_static::version!()),
            _ => return Ok(None),
        };

        fn read_to_vec(mut reader: impl std::io::Read) -> std::io::Result<Vec<u8>> {
            let mut res = Vec::new();
            reader.read_to_end(&mut res)?;
            Ok(res)
        }

        let prover_key = read_to_vec(
            &mut self
                .0
                .get_file(
                    &format!("{file_root}.prover"),
                    &format!("failed to find prover key {file_root}.prover"),
                )
                .await?,
        )?;
        let verifier_key = read_to_vec(
            &mut self
                .0
                .get_file(
                    &format!("{file_root}.verifier"),
                    &format!("failed to find verifier key {file_root}.verifier"),
                )
                .await?,
        )?;
        let ir_source = read_to_vec(
            &mut self
                .0
                .get_file(
                    &format!("{file_root}.bzkir"),
                    &format!("failed to find IR {file_root}.bzkir"),
                )
                .await?,
        )?;

        Ok(Some(ProvingKeyMaterial {
            ir_source,
            prover_key,
            verifier_key,
        }))
    }
}

impl OwsProver {
    pub fn from_env() -> Result<Self, PayError> {
        let dir: std::path::PathBuf = std::env::var("OWS_MIDNIGHT_PROVING_KEY_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var_os("HOME")
                    .or_else(|| std::env::var_os("USERPROFILE"))
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| std::path::PathBuf::from("."));
                home.join(".cache")
                    .join("ows-pay")
                    .join("midnight-proving-keys")
            });

        Ok(Self {
            rng: StdRng::from_entropy(),
            provider: MidnightDataProvider {
                fetch_mode: data_provider::FetchMode::OnDemand,
                base_url: data_provider::BASE_URL.clone(),
                output_mode: data_provider::OutputMode::Log,
                expected_data: {
                    let mut v = midnight_ledger::dust::DUST_EXPECTED_FILES.to_vec();
                    v.extend_from_slice(midnight_zswap::ZSWAP_EXPECTED_FILES);
                    v
                },
                dir,
            },
        })
    }
}

impl ProvingProvider for OwsProver {
    async fn check(&self, preimage: &ProofPreimage) -> Result<Vec<Option<usize>>, anyhow::Error> {
        let resolver = OwsResolver(self.provider.clone());
        let lp = LocalProvingProvider {
            rng: StdRng::from_entropy(),
            resolver: &resolver,
            params: &self.provider,
        };
        lp.check(preimage).await
    }

    async fn prove(
        self,
        preimage: &ProofPreimage,
        overwrite_binding_input: Option<Fr>,
    ) -> Result<Proof, anyhow::Error> {
        let mut rng = self.rng;
        let provider = self.provider;
        let resolver = OwsResolver(provider.clone());
        let lp = LocalProvingProvider {
            rng: rng.split(),
            resolver: &resolver,
            params: &provider,
        };
        lp.prove(preimage, overwrite_binding_input).await
    }

    fn split(&mut self) -> Self {
        Self {
            rng: self.rng.split(),
            provider: self.provider.clone(),
        }
    }
}
