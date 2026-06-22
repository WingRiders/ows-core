pub mod chains;
pub mod error;
pub mod key_ops;
pub mod key_store;
pub mod migrate;
pub mod nano_rpc;
pub mod near_rpc;
pub mod ops;
pub mod policy_engine;
pub mod policy_store;
mod sui_grpc;
pub mod types;
pub mod vault;

// Re-export the primary API.
pub use error::OwsLibError;
pub use ops::*;
pub use types::*;

// Midnight wallet helpers (also available under `chains::midnight`).
pub use chains::midnight::{
    decrypt_midnight_auxiliary_seeds_with_fallback, decrypt_midnight_dust_seed,
    decrypt_midnight_dust_seed_with_fallback, decrypt_midnight_shielded_seed,
    decrypt_midnight_shielded_seed_with_fallback, midnight_sync_scope_for_wallet,
    prepare_midnight_owner_tx_context, prepare_owner_tx_context,
    sign_and_send_prepared_owner_transaction, sign_prepared_owner_transaction, DecodedTxInput,
    MidnightOwnerTxContext, OwnerTxContext,
};
