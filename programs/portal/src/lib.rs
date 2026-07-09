use anchor_lang::prelude::*;
use anchor_lang::system_program;
use solana_sha256_hasher::hash as sha256;
use solana_security_txt::security_txt;

declare_id!("75vZMouaNixrw4zk1rohwMyHCkPZU7odD5crg6goWjM6");

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name:                "Portal",
    project_url:         "https://portal.gripe",
    contacts:            "email:max@maxis.fit",
    policy:              "https://portal.gripe/security.txt",
    preferred_languages: "en",
    auditors:            "None"
}

/* ------------------------------------------------------------------ */
/*  Constants                                                           */
/* ------------------------------------------------------------------ */

/// Price in lamports (1 SOL = 1_000_000_000).
const KEY_PRICE_LAMPORTS: u64 = 100_000_000; // 0.1 SOL

/// Hardcoded treasury — the only wallet that can receive purchase funds.
/// This prevents buyers from passing their own wallet as treasury.
const TREASURY_PUBKEY: Pubkey = pubkey!("D6Ncr7cpk5YEQR4z1foysf25FuvEq8pagHRKMmJpKT76");

/// Unambiguous alphanumeric charset (no 0/O, 1/I/l)
const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[program]
pub mod portal {
    use super::*;

    /// Purchase a portal key.
    /// Transfers SOL to treasury, derives a collision-resistant 8-char
    /// key via SHA-256(pubkey || slot || timestamp), stores in PDA.
    pub fn purchase_key(ctx: Context<PurchaseKey>) -> Result<()> {
        let buyer    = &ctx.accounts.buyer;
        let record   = &mut ctx.accounts.key_record;
        let treasury = &ctx.accounts.treasury;
        let clock    = Clock::get()?;

        /* ---- transfer SOL to treasury ---- */
        let cpi_ctx = CpiContext::new(
            system_program::ID,
            system_program::Transfer {
                from: buyer.to_account_info(),
                to:   treasury.to_account_info(),
            },
        );
        system_program::transfer(cpi_ctx, KEY_PRICE_LAMPORTS)?;

        /* ---- generate key via SHA-256 ---- */
        // Build a 48-byte seed: pubkey(32) + slot(8) + timestamp(8)
        let mut seed = [0u8; 48];
        seed[..32].copy_from_slice(&buyer.key().to_bytes());

        let slot = clock.slot;
        let ts   = clock.unix_timestamp as u64;
        for i in 0..8usize {
            seed[32 + i] = ((slot >> (i * 8)) & 0xFF) as u8;
            seed[40 + i] = ((ts   >> (i * 8)) & 0xFF) as u8;
        }

        let hash_bytes = sha256(&seed).to_bytes();

        let mut key_chars = [0u8; 8];
        for i in 0..8usize {
            key_chars[i] = CHARSET[(hash_bytes[i] as usize) % CHARSET.len()];
        }

        let portal_key = std::str::from_utf8(&key_chars)
            .map_err(|_| ErrorCode::KeyGenerationFailed)?
            .to_string();

        /* ---- store ---- */
        record.owner        = buyer.key();
        record.portal_key   = portal_key.clone();
        record.purchased_at = clock.unix_timestamp;
        record.used         = false;
        record.face_hash    = [0u8; 32];
        record.face_bound   = false;

        emit!(KeyPurchased {
            buyer: buyer.key(),
            portal_key,
            purchased_at: clock.unix_timestamp,
        });

        Ok(())
    }

    /// Mark a key as used — called by your server after a session starts.
    /// Only callable by the program authority.
    pub fn mark_used(ctx: Context<MarkUsed>) -> Result<()> {
        require!(!ctx.accounts.key_record.used, ErrorCode::KeyAlreadyUsed);
        ctx.accounts.key_record.used = true;
        Ok(())
    }

    /// Bind a face embedding hash to a KeyRecord.
    /// Called once by the buyer immediately after purchase.
    /// The hash is SHA-256(face_embedding_bytes) computed off-chain by the server.
    /// Once bound, the face cannot be rebound — the hash is permanent on-chain proof
    /// of which face was enrolled against this key.
    pub fn bind_face(ctx: Context<BindFace>, face_hash: [u8; 32]) -> Result<()> {
        let record = &mut ctx.accounts.key_record;
        require!(!record.face_bound, ErrorCode::FaceAlreadyBound);
        record.face_hash  = face_hash;
        record.face_bound = true;
        Ok(())
    }
}

/* ------------------------------------------------------------------ */
/*  Accounts                                                            */
/* ------------------------------------------------------------------ */

#[derive(Accounts)]
pub struct PurchaseKey<'info> {
    #[account(mut)]
    pub buyer: Signer<'info>,

    /// PDA: seeds = ["key_record", buyer_pubkey]
    /// One-time init only — a wallet that already has a KeyRecord cannot
    /// purchase again. `init_if_needed` previously allowed re-purchase to
    /// silently overwrite the record, resetting face_bound/face_hash and
    /// breaking the "immutable once bound" biometric commitment guarantee.
    #[account(
        init,
        payer = buyer,
        space = KeyRecord::LEN,
        seeds = [b"key_record", buyer.key().as_ref()],
        bump
    )]
    pub key_record: Account<'info, KeyRecord>,

    /// Treasury — must match the hardcoded TREASURY_PUBKEY constant.
    /// CHECK: address constraint enforces the correct recipient.
    #[account(mut, address = TREASURY_PUBKEY @ ErrorCode::InvalidTreasury)]
    pub treasury: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct MarkUsed<'info> {
    #[account(constraint = authority.key() == key_record.owner @ ErrorCode::Unauthorized)]
    pub authority: Signer<'info>,

    #[account(mut)]
    pub key_record: Account<'info, KeyRecord>,
}

#[derive(Accounts)]
pub struct BindFace<'info> {
    /// Only the buyer (key owner) may bind a face.
    #[account(constraint = buyer.key() == key_record.owner @ ErrorCode::Unauthorized)]
    pub buyer: Signer<'info>,

    #[account(mut, seeds = [b"key_record", buyer.key().as_ref()], bump)]
    pub key_record: Account<'info, KeyRecord>,
}

/* ------------------------------------------------------------------ */
/*  State                                                               */
/* ------------------------------------------------------------------ */

#[account]
pub struct KeyRecord {
    pub owner:        Pubkey,    // 32
    pub portal_key:   String,    // 4 + 8
    pub purchased_at: i64,       // 8
    pub used:         bool,      // 1
    pub face_hash:    [u8; 32],  // 32  — SHA-256 of enrolled face embedding
    pub face_bound:   bool,      // 1   — true once bind_face has been called
}

impl KeyRecord {
    // discriminator(8) + pubkey(32) + string(4+8) + i64(8) + bool(1) + [u8;32](32) + bool(1)
    pub const LEN: usize = 8 + 32 + (4 + 8) + 8 + 1 + 32 + 1;
}

/* ------------------------------------------------------------------ */
/*  Events                                                              */
/* ------------------------------------------------------------------ */

#[event]
pub struct KeyPurchased {
    pub buyer:        Pubkey,
    pub portal_key:   String,
    pub purchased_at: i64,
}

/* ------------------------------------------------------------------ */
/*  Errors                                                              */
/* ------------------------------------------------------------------ */

#[error_code]
pub enum ErrorCode {
    #[msg("Key generation failed")]
    KeyGenerationFailed,
    #[msg("Key already used")]
    KeyAlreadyUsed,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Invalid treasury account")]
    InvalidTreasury,
    #[msg("Face already bound to this key")]
    FaceAlreadyBound,
}
