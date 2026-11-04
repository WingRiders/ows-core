import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  generateMnemonic,
  deriveAddress,
  createWallet,
  listWallets,
  getWallet,
  deleteWallet,
  exportWallet,
  renameWallet,
  importWalletMnemonic,
  importWalletPrivateKey,
  signTransaction,
  signMessage,
  signHash,
  signAuthorization,
  signTypedData,
  createPolicy,
  listPolicies,
  getPolicy,
  deletePolicy,
  createApiKey,
  listApiKeys,
  revokeApiKey,
  createCredential,
  importCredential,
  listCredentials,
  getCredential,
  deleteCredential,
  signWithCredential,
} from '../index.js';

describe('@open-wallet-standard/core', () => {
  let vaultDir;

  before(() => {
    vaultDir = mkdtempSync(join(tmpdir(), 'ows-node-test-'));
  });

  after(() => {
    rmSync(vaultDir, { recursive: true, force: true });
  });

  // ---- Mnemonic ----

  it('generates a 12-word mnemonic', () => {
    const phrase = generateMnemonic(12);
    assert.equal(phrase.split(' ').length, 12);
  });

  it('generates a 24-word mnemonic', () => {
    const phrase = generateMnemonic(24);
    assert.equal(phrase.split(' ').length, 24);
  });

  it('derives addresses for all chains', () => {
    const phrase = generateMnemonic(12);
    for (const chain of ['evm', 'solana', 'sui', 'bitcoin', 'cosmos', 'tron', 'ton', 'filecoin', 'xrpl', 'nano', 'near', 'cardano']) {
      const addr = deriveAddress(phrase, chain);
      assert.ok(addr.length > 0, `address should be non-empty for ${chain}`);
    }
  });

  it('routes Midnight address derivation through the binding', () => {
    const phrase = generateMnemonic(12);

    // Address derivation reaches the Midnight signer and re-encodes per network HRP.
    const preview = deriveAddress(phrase, 'midnight:preview');
    assert.ok(preview.startsWith('mn_addr_preview1'), `expected preview HRP, got ${preview}`);
    const mainnet = deriveAddress(phrase, 'midnight:mainnet');
    assert.ok(mainnet.startsWith('mn_addr1'), `expected mainnet HRP, got ${mainnet}`);
  });

  it('signs a Midnight message through the binding, sealing no transaction', () => {
    const phrase = generateMnemonic(12);

    // Owner-mode message signing works through the binding (BIP-340, x-only pubkey prefixed
    // to the signature → 96 bytes → 192 hex chars), and the SignResult carries the
    // Midnight-only `transaction` field — undefined for a message (only `sign tx` seals a tx).
    // Uses an isolated vault so it doesn't perturb the shared-vault wallet-count assertions.
    const mnVault = mkdtempSync(join(tmpdir(), 'ows-node-mn-'));
    try {
      importWalletMnemonic('mn-node', phrase, undefined, undefined, mnVault);
      const result = signMessage('mn-node', 'midnight:preview', 'hello midnight', '', undefined, undefined, mnVault);
      assert.equal(result.signature.length, 192, 'midnight signature = pubkey(32)+sig(64) as hex');
      assert.equal(result.transaction, undefined, 'a message seals no transaction');
    } finally {
      rmSync(mnVault, { recursive: true, force: true });
    }
  });

  // ---- Universal wallet lifecycle ----

  it('creates a universal wallet with 16 accounts', () => {
    const wallet = createWallet('lifecycle-test', undefined, 12, vaultDir);
    assert.equal(wallet.name, 'lifecycle-test');
    assert.equal(wallet.accounts.length, 16);

    const chainIds = wallet.accounts.map((a) => a.chainId);
    assert.ok(chainIds.some((c) => c.startsWith('eip155:')));
    assert.ok(chainIds.some((c) => c.startsWith('solana:')));
    assert.ok(chainIds.some((c) => c.startsWith('sui:')));
    assert.ok(chainIds.some((c) => c.startsWith('bip122:')));
    assert.ok(chainIds.some((c) => c.startsWith('cosmos:')));
    assert.ok(chainIds.some((c) => c.startsWith('tron:')));
    assert.ok(chainIds.some((c) => c.startsWith('ton:')));
    assert.ok(chainIds.some((c) => c.startsWith('spark:')));
    assert.ok(chainIds.some((c) => c.startsWith('fil:')));
    assert.ok(chainIds.some((c) => c.startsWith('xrpl:')));
    assert.ok(chainIds.some((c) => c.startsWith('nano:')));
    assert.ok(chainIds.some((c) => c.startsWith('near:')));
    assert.ok(chainIds.some((c) => c.startsWith('cip34:')));
    assert.ok(chainIds.some((c) => c.startsWith('midnight:')));

    // List
    const wallets = listWallets(vaultDir);
    assert.equal(wallets.length, 1);
    assert.equal(wallets[0].id, wallet.id);

    // Get by name
    const found = getWallet('lifecycle-test', vaultDir);
    assert.equal(found.id, wallet.id);

    // Rename
    renameWallet('lifecycle-test', 'renamed', vaultDir);
    const renamed = getWallet('renamed', vaultDir);
    assert.equal(renamed.id, wallet.id);

    // Export mnemonic
    const secret = exportWallet('renamed', undefined, vaultDir);
    assert.equal(secret.split(' ').length, 12);

    // Delete
    deleteWallet('renamed', vaultDir);
    assert.equal(listWallets(vaultDir).length, 0);
  });

  // ---- Mnemonic import round-trip ----

  it('imports a mnemonic and produces same addresses', () => {
    const phrase = generateMnemonic(12);
    const expectedEvm = deriveAddress(phrase, 'evm');
    const expectedSol = deriveAddress(phrase, 'solana');

    const wallet = importWalletMnemonic('mn-import', phrase, undefined, undefined, vaultDir);
    assert.equal(wallet.name, 'mn-import');
    assert.equal(wallet.accounts.length, 16);

    const evmAcct = wallet.accounts.find((a) => a.chainId.startsWith('eip155:'));
    assert.equal(evmAcct.address, expectedEvm);

    const solAcct = wallet.accounts.find((a) => a.chainId.startsWith('solana:'));
    assert.equal(solAcct.address, expectedSol);

    deleteWallet('mn-import', vaultDir);
  });

  // ---- Private key import (secp256k1) ----

  it('imports a secp256k1 private key with all 15 accounts', () => {
    const privkey = '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
    const wallet = importWalletPrivateKey('pk-secp', privkey, undefined, vaultDir, 'evm');

    assert.equal(wallet.name, 'pk-secp');
    assert.equal(wallet.accounts.length, 15, 'should have all 15 chain accounts');

    // Sign on EVM (provided key's curve)
    const evmSig = signMessage('pk-secp', 'evm', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(evmSig.signature.length > 0);

    // Sign on Solana (generated key's curve)
    const solSig = signMessage('pk-secp', 'solana', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(solSig.signature.length > 0);

    // Export returns JSON with all keys
    const exported = JSON.parse(exportWallet('pk-secp', undefined, vaultDir));
    assert.equal(exported.secp256k1, privkey);
    assert.ok(exported.ed25519.length === 64, 'should have 32-byte ed25519 key in hex');

    deleteWallet('pk-secp', vaultDir);
  });

  // ---- Private key import (ed25519) ----

  it('imports an ed25519 private key with all 15 accounts', () => {
    const privkey = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
    const wallet = importWalletPrivateKey('pk-ed', privkey, undefined, vaultDir, 'solana');

    assert.equal(wallet.accounts.length, 15);

    // Sign on Solana (provided key)
    const solSig = signMessage('pk-ed', 'solana', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(solSig.signature.length > 0);

    // Sign on EVM (generated key)
    const evmSig = signMessage('pk-ed', 'evm', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(evmSig.signature.length > 0);

    // Sign on TON (same ed25519 key)
    const tonSig = signMessage('pk-ed', 'ton', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(tonSig.signature.length > 0);

    deleteWallet('pk-ed', vaultDir);
  });

  // ---- Private key import (ed25519-bip32) ----

  it('imports an ed25519-bip32 private key with all 15 accounts', () => {
    const privkey = 'f8a29231ee38d6c5bf715d5bac21c750577aa3798b22d79d65bf97d6fadea15adcd1ee1abdf78bd4be64731a12deb94d3671784112eb6f364b871851fd1c9a247384db9ad6003bbd08b3b1ddc0d07a597293ff85e961bf252b331262eddfad0d';
    const wallet = importWalletPrivateKey('pk-ed-bip32', privkey, undefined, vaultDir, 'cardano');

    assert.equal(wallet.accounts.length, 15);

    // Sign on Cardano (provided key)
    const cardanoSig = signMessage('pk-ed-bip32', 'cardano', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(cardanoSig.signature.length > 0);

    // Sign on EVM (generated key)
    const evmSig = signMessage('pk-ed-bip32', 'evm', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(evmSig.signature.length > 0);

    // Sign on TON (same ed25519 key)
    const tonSig = signMessage('pk-ed-bip32', 'ton', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(tonSig.signature.length > 0);

    // Sign on Solana (generated key)
    const solSig = signMessage('pk-ed-bip32', 'solana', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(solSig.signature.length > 0);

    deleteWallet('pk-ed-bip32', vaultDir);
  });

  // ---- Private key import (all curves) ----

  it('imports all curve keys explicitly', () => {
    const secpKey = '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
    const edKey = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
    const edBip32Key = 'f8a29231ee38d6c5bf715d5bac21c750577aa3798b22d79d65bf97d6fadea15adcd1ee1abdf78bd4be64731a12deb94d3671784112eb6f364b871851fd1c9a247384db9ad6003bbd08b3b1ddc0d07a597293ff85e961bf252b331262eddfad0d';

    const wallet = importWalletPrivateKey(
      'pk-all', '', undefined, vaultDir, undefined, secpKey, edKey, edBip32Key
    );

    assert.equal(wallet.name, 'pk-all');
    assert.equal(wallet.accounts.length, 15, 'should have all 15 chain accounts');

    // Sign on EVM (secp256k1 key)
    const evmSig = signMessage('pk-all', 'evm', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(evmSig.signature.length > 0);

    // Sign on Solana (ed25519 key)
    const solSig = signMessage('pk-all', 'solana', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(solSig.signature.length > 0);

    // Sign on Cardano (ed25519-bip32 key)
    const cardanoSig = signMessage('pk-all', 'cardano', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(cardanoSig.signature.length > 0);

    // Export returns all provided keys
    const exported = JSON.parse(exportWallet('pk-all', undefined, vaultDir));
    assert.equal(exported.secp256k1, secpKey);
    assert.equal(exported.ed25519, edKey);
    assert.equal(exported.ed25519_bip32, edBip32Key);

    deleteWallet('pk-all', vaultDir);
  });

  // ---- Signing all chains ----

  it('signs messages on all chains', () => {
    createWallet('all-chain-signer', undefined, 12, vaultDir);

    // XRPL and Nano are excluded here because their signers explicitly do not
    // support generic off-chain message signing without a defined convention.
    // NEAR's V1 sign_message is raw ed25519 over the bytes (NEP-413 is a follow-up).
    for (const chain of ['evm', 'solana', 'sui', 'bitcoin', 'cosmos', 'tron', 'ton', 'filecoin', 'near']) {
      const result = signMessage('all-chain-signer', chain, 'test', undefined, undefined, undefined, vaultDir);
      assert.ok(result.signature.length > 0, `signature should be non-empty for ${chain}`);
    }

    deleteWallet('all-chain-signer', vaultDir);
  });

  it('signs transactions on all chains', () => {
    createWallet('tx-signer', undefined, 12, vaultDir);
    const txHex = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
    // Solana extract_signable_bytes expects a valid wire format:
    // [compact-u16 sig count][64-byte sig slots...][message...]
    // Build a minimal tx with 1 sig slot (0x01) + 64 zero bytes + a message.
    const solTxHex = '01' + '00'.repeat(64) + 'deadbeefdeadbeef';
    // Nano state block: 176-byte canonical layout (preamble + account + previous
    // + representative + balance + link).
    // https://docs.nano.org/integration-guides/the-basics/#self-signed-blocks
    const nanoTxHex =
      `${'00'.repeat(31)}06` +
      `${'01'.repeat(32)}` +
      `${'00'.repeat(32)}` +
      `${'02'.repeat(32)}` +
      '00000000033b2e3c9fd0803ce8000000' +
      `${'03'.repeat(32)}`;

    // NEAR transactions have no envelope; signer hashes via sha256 then ed25519
    // signs the digest. Any non-empty bytes verify the signing pipeline.
    const nearTxHex = '42'.repeat(80);

    // Valid Cardano Conway-era `FixedTransaction` CBOR fixture (from cardano-serialization-lib tests).
    const cardanoTxHex = "84a700818258208b9c96823c19f2047f32210a330434b3d163e194ea17b2b702c0667f6fea7a7a000d80018182581d6138fe1dd1d91221a199ff0dacf41fdd5b87506b533d00e70fae8dae8f1abfbac06a021a0002b645031a03962de305a1581de1b3cabd3914ef99169ace1e8b545b635f809caa35f8b6c8bc69ae48061abf4009040e80a100828258207dc05ac55cdfb9cc24571d491d3a3bdbd7d48489a916d27fce3ffe5c9af1b7f55840d7eda8457f1814fe3333b7b1916e3b034e6d480f97f4f286b1443ef72383279718a3a3fddf127dae0505b01a48fd9ffe0f52d9d8c46d02bcb85d1d106c13aa048258201b3d6e1236891a921abf1a3f90a9fb1b2568b1096b6cd6d3eaaeb0ef0ee0802f58401ce4658303c3eb0f2b9705992ccd62de30423ade90219e2c4cfc9eb488c892ea28ba3110f0c062298447f4f6365499d97d31207075f9815c3fe530bd9a927402f5f6";

    // XRPL signing decodes the tx to inject SigningPubKey, so it needs a real
    // binary-encoded unsigned Payment (no SigningPubKey/TxnSignature).
    const xrplTxHex =
      '12000024000000016140000000000F424068400000000000000C8114AFF3C2E33458B30714CA16FFEE19952DD35C17C883145720939C1336A7356A70ED861D5934345C6B6360';

    const txHexByChain = {
      solana: solTxHex,
      nano: nanoTxHex,
      near: nearTxHex,
      xrpl: xrplTxHex,
      cardano: cardanoTxHex,
    };

    for (const chain of ['evm', 'solana', 'sui', 'bitcoin', 'cosmos', 'tron', 'ton', 'filecoin', 'xrpl', 'nano', 'near', 'cardano']) {
      const hex = txHexByChain[chain] ?? txHex;
      const result = signTransaction('tx-signer', chain, hex, undefined, undefined, vaultDir);
      assert.ok(result.signature.length > 0, `signature should be non-empty for ${chain}`);
    }

    deleteWallet('tx-signer', vaultDir);
  });

  it('signs raw hashes and EIP-7702 authorizations in owner mode', () => {
    const privkey = '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
    const wallet = importWalletPrivateKey('hash-owner', privkey, undefined, vaultDir, 'evm');

    const hashSig = signHash(wallet.id, 'base', '11'.repeat(32), undefined, undefined, vaultDir);
    assert.ok(hashSig.signature.length > 0);
    assert.ok(hashSig.recoveryId === 0 || hashSig.recoveryId === 1);

    const authSig = signAuthorization(
      wallet.id,
      'base',
      '0x1111111111111111111111111111111111111111',
      '7',
      undefined,
      undefined,
      vaultDir,
    );
    assert.ok(authSig.signature.length > 0);
    assert.ok(authSig.recoveryId === 0 || authSig.recoveryId === 1);

    deleteWallet(wallet.id, vaultDir);
  });

  // ---- Determinism ----

  it('produces deterministic signatures', () => {
    createWallet('det-test', undefined, 12, vaultDir);

    const sig1 = signMessage('det-test', 'evm', 'hello', undefined, undefined, undefined, vaultDir);
    const sig2 = signMessage('det-test', 'evm', 'hello', undefined, undefined, undefined, vaultDir);
    assert.equal(sig1.signature, sig2.signature);

    deleteWallet('det-test', vaultDir);
  });

  // ---- Error handling ----

  it('rejects duplicate wallet names', () => {
    createWallet('dup-name', undefined, 12, vaultDir);
    assert.throws(() => createWallet('dup-name', undefined, 12, vaultDir));
    deleteWallet('dup-name', vaultDir);
  });

  it('rejects non-existent wallet', () => {
    assert.throws(() => getWallet('nonexistent', vaultDir));
    assert.throws(() => signMessage('nonexistent', 'evm', 'x', undefined, undefined, undefined, vaultDir));
  });

  it('rejects invalid private key hex', () => {
    assert.throws(() => importWalletPrivateKey('bad', 'not-hex', undefined, vaultDir));
  });

  // ---- Policy engine: API key signing ----

  it('creates a policy, API key by wallet name, and signs with the token', () => {
    const wallet = createWallet('policy-test', undefined, 12, vaultDir);

    // Register a policy allowing only Base
    createPolicy(JSON.stringify({
      id: 'test-base-only',
      name: 'Base Only',
      version: 1,
      created_at: '2026-03-22T00:00:00Z',
      rules: [
        { type: 'allowed_chains', chain_ids: ['eip155:8453', 'eip155:84532'] },
      ],
      action: 'deny',
    }), vaultDir);

    // Create API key by wallet name
    const key = createApiKey('test-agent', [wallet.id], ['test-base-only'], '', null, vaultDir);
    assert.ok(key.token.startsWith('ows_key_'));
    assert.equal(key.name, 'test-agent');

    // Sign on allowed chain — should succeed
    const sig = signTransaction(wallet.id, 'base', 'deadbeef', key.token, null, vaultDir);
    assert.ok(sig.signature.length > 0);

    // Sign on denied chain — should fail
    assert.throws(
      () => signTransaction(wallet.id, 'ethereum', 'deadbeef', key.token, null, vaultDir),
      (err) => err.message.includes('not in allowlist'),
    );

    // Owner mode still works on any chain
    const ownerSig = signTransaction(wallet.id, 'ethereum', 'deadbeef', '', null, vaultDir);
    assert.ok(ownerSig.signature.length > 0);

    // Revoke and verify token is dead
    revokeApiKey(key.id, vaultDir);
    assert.throws(
      () => signTransaction(wallet.id, 'base', 'deadbeef', key.token, null, vaultDir),
      (err) => err.message.includes('API key not found'),
    );

    // Cleanup
    deletePolicy('test-base-only', vaultDir);
    deleteWallet(wallet.id, vaultDir);
  });

  it('signs with an API key for a wallet imported from a private key', () => {
    createPolicy(JSON.stringify({
      id: 'test-imported-wallet',
      name: 'Imported Wallet',
      version: 1,
      created_at: '2026-03-31T00:00:00Z',
      rules: [
        { type: 'allowed_chains', chain_ids: ['eip155:8453'] },
      ],
      action: 'deny',
    }), vaultDir);

    const wallet = importWalletPrivateKey(
      'policy-imported-wallet',
      'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
      '',
      vaultDir,
      'evm',
    );
    const key = createApiKey(
      'imported-wallet-agent',
      [wallet.id],
      ['test-imported-wallet'],
      '',
      null,
      vaultDir,
    );

    const msgSig = signMessage(
      wallet.id,
      'base',
      'hello',
      key.token,
      undefined,
      undefined,
      vaultDir,
    );
    assert.ok(msgSig.signature.length > 0);

    const txSig = signTransaction(wallet.id, 'base', 'deadbeef', key.token, null, vaultDir);
    assert.ok(txSig.signature.length > 0);

    revokeApiKey(key.id, vaultDir);
    deletePolicy('test-imported-wallet', vaultDir);
    deleteWallet(wallet.id, vaultDir);
  });

  it('signs EIP-712 typed data with an API key token', () => {
    const wallet = createWallet('typed-data-api', undefined, 12, vaultDir);

    // Register a policy allowing Base chains
    createPolicy(JSON.stringify({
      id: 'td-base-only',
      name: 'Base Only',
      version: 1,
      created_at: '2026-03-22T00:00:00Z',
      rules: [
        { type: 'allowed_chains', chain_ids: ['eip155:8453', 'eip155:84532'] },
      ],
      action: 'deny',
    }), vaultDir);

    // Create API key bound to the wallet and policy
    const key = createApiKey('td-agent', [wallet.id], ['td-base-only'], '', null, vaultDir);
    assert.ok(key.token.startsWith('ows_key_'));

    // EIP-712 typed data (the standard "Mail" example)
    const typedDataJson = JSON.stringify({
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      },
      primaryType: 'Mail',
      domain: {
        name: 'Ether Mail',
        version: '1',
        chainId: 8453,
        verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
      },
      message: {
        from: { name: 'Cow', wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826' },
        to: { name: 'Bob', wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB' },
        contents: 'Hello, Bob!',
      },
    });

    // Sign on allowed chain — should succeed
    const sig = signTypedData(wallet.id, 'base', typedDataJson, key.token, null, vaultDir);
    assert.ok(sig.signature.length > 0, 'signature should be non-empty');
    assert.ok(sig.recoveryId != null, 'recoveryId should be present for EIP-712');

    // Sign on denied chain — should fail
    // Build typed data with chainId=1 matching ethereum so the domain check passes
    // and AllowedChains (base-only) correctly denies
    const ethTypedDataJson = JSON.stringify({
      ...JSON.parse(typedDataJson),
      domain: { ...JSON.parse(typedDataJson).domain, chainId: 1 },
    });
    assert.throws(
      () => signTypedData(wallet.id, 'ethereum', ethTypedDataJson, key.token, null, vaultDir),
      (err) => err.message.includes('not in allowlist'),
    );

    // Cleanup
    revokeApiKey(key.id, vaultDir);
    deletePolicy('td-base-only', vaultDir);
    deleteWallet(wallet.id, vaultDir);
  });

  it('enforces AllowedTypedDataContracts through the node binding', () => {
    const wallet = createWallet('typed-data-contract-api', undefined, 12, vaultDir);

    createPolicy(JSON.stringify({
      id: 'td-contract-only',
      name: 'Typed Data Contract Only',
      version: 1,
      created_at: '2026-03-22T00:00:00Z',
      rules: [
        { type: 'allowed_chains', chain_ids: ['eip155:8453'] },
        {
          type: 'allowed_typed_data_contracts',
          contracts: ['0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC'],
        },
      ],
      action: 'deny',
    }), vaultDir);

    const key = createApiKey('td-contract-agent', [wallet.id], ['td-contract-only'], '', null, vaultDir);

    const typedData = {
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],
        Mail: [{ name: 'contents', type: 'string' }],
      },
      primaryType: 'Mail',
      domain: {
        name: 'Ether Mail',
        version: '1',
        chainId: 8453,
        verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
      },
      message: {
        contents: 'Hello, Bob!',
      },
    };

    const allowed = signTypedData(
      wallet.id,
      'base',
      JSON.stringify(typedData),
      key.token,
      null,
      vaultDir,
    );
    assert.ok(allowed.signature.length > 0);

    const deniedTypedData = {
      ...typedData,
      domain: {
        ...typedData.domain,
        verifyingContract: '0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC',
      },
    };

    assert.throws(
      () => signTypedData(wallet.id, 'base', JSON.stringify(deniedTypedData), key.token, null, vaultDir),
      (err) => err.message.includes('not in allowed list'),
    );

    revokeApiKey(key.id, vaultDir);
    deletePolicy('td-contract-only', vaultDir);
    deleteWallet(wallet.id, vaultDir);
  });

  it('executable policy gates signing', () => {
    const wallet = createWallet('exe-test', undefined, 12, vaultDir);

    // Write a deny script
    const scriptPath = join(vaultDir, 'deny.sh');
    writeFileSync(scriptPath, '#!/bin/sh\ncat > /dev/null\necho \'{"allow":false,"reason":"custom: blocked"}\'\n', { mode: 0o755 });

    createPolicy(JSON.stringify({
      id: 'test-exe-deny',
      name: 'Executable Deny',
      version: 1,
      created_at: '2026-03-22T00:00:00Z',
      rules: [],
      executable: scriptPath,
      action: 'deny',
    }), vaultDir);

    const key = createApiKey('exe-agent', [wallet.id], ['test-exe-deny'], '', null, vaultDir);

    assert.throws(
      () => signTransaction(wallet.id, 'evm', 'deadbeef', key.token, null, vaultDir),
      (err) => err.message.includes('custom: blocked'),
    );

    revokeApiKey(key.id, vaultDir);
    deletePolicy('test-exe-deny', vaultDir);
    deleteWallet(wallet.id, vaultDir);
  });

  it('signs raw hashes and authorizations through the API-key path', () => {
    const wallet = createWallet('hash-policy-test', undefined, 12, vaultDir);

    createPolicy(JSON.stringify({
      id: 'test-hash-base-only',
      name: 'Base Only Hash',
      version: 1,
      created_at: '2026-03-22T00:00:00Z',
      rules: [
        { type: 'allowed_chains', chain_ids: ['eip155:8453'] },
      ],
      action: 'deny',
    }), vaultDir);

    const key = createApiKey('hash-agent', [wallet.id], ['test-hash-base-only'], '', null, vaultDir);

    const hashSig = signHash(wallet.id, 'base', '22'.repeat(32), key.token, null, vaultDir);
    assert.ok(hashSig.signature.length > 0);

    const authSig = signAuthorization(
      wallet.id,
      'base',
      '0x1111111111111111111111111111111111111111',
      '7',
      key.token,
      null,
      vaultDir,
    );
    assert.ok(authSig.signature.length > 0);

    assert.throws(
      () => signAuthorization(
        wallet.id,
        'ethereum',
        '0x1111111111111111111111111111111111111111',
        '7',
        key.token,
        null,
        vaultDir,
      ),
      (err) => err.message.includes('not in allowlist'),
    );

    revokeApiKey(key.id, vaultDir);
    deletePolicy('test-hash-base-only', vaultDir);
    deleteWallet(wallet.id, vaultDir);
  });

  // ---- Credentials ----

  const ACCOUNT = 'a19612afc371b1a4d2fc2410377da895ff7ca406e74449b75dcc32a2b6df7964';
  const COLOR = '5cd36fe5ed159246257b476bb67bc8266290581ef3844fcabd7c134b3f8b03ea';
  const RECIPIENT = 'b0c1d2e3f405162738495a6b7c8d9eafb0c1d2e3f405162738495a6b7c8d9e00';

  const withdrawUnshielded = () => JSON.stringify({
    scheme: 'midnight:account:auth:v1',
    account: ACCOUNT,
    circuit: 'withdraw_unshielded',
    args: [
      { type: 'Bytes<32>', value: COLOR },
      { type: 'Uint<128>', value: '3000000' },
      { type: 'UserAddress', value: `0x${RECIPIENT}` },
    ],
    witnesses: [],
    authNonce: '3',
  });

  it('creates, lists, signs with and deletes a credential', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ows-node-cred-'));
    try {
      const cred = createCredential('passport-device', 'midnight', null, 'pw', dir);
      assert.equal(cred.name, 'passport-device');
      assert.equal(cred.chain, 'midnight');
      assert.equal(cred.origin, 'generated');
      assert.equal(cred.publicKey.length, 128);
      assert.equal(Object.keys(cred).some((k) => /secret|crypto/i.test(k)), false);

      const listed = listCredentials(dir);
      assert.equal(listed.length, 1);
      assert.equal(listed[0].publicKey, cred.publicKey);

      const got = getCredential('passport-device', dir);
      assert.equal(got.id, cred.id);

      const sig = signWithCredential('passport-device', 'midnight', withdrawUnshielded(), 'pw', dir);
      assert.deepEqual(Object.keys(sig).sort(), ['grindNonce', 'pk', 'scheme', 'sigR', 'sigS', 'signature']);
      assert.equal(sig.scheme, 'midnight:account:auth:v1');
      assert.equal(sig.pk, cred.publicKey);
      assert.match(sig.sigR, /^[0-9a-f]{128}$/);
      assert.match(sig.sigS, /^[0-9a-f]{64}$/);
      assert.ok(Number.isInteger(sig.grindNonce));
      assert.equal(sig.signature, sig.sigR + sig.sigS + sig.grindNonce.toString(16).padStart(16, '0'));

      deleteCredential(cred.id, dir);
      assert.equal(listCredentials(dir).length, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('imports a credential and marks it imported', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ows-node-cred-'));
    try {
      const cred = importCredential('imported', 'midnight', '00'.repeat(31) + '7b', null, 'pw', dir);
      assert.equal(cred.origin, 'imported');
      assert.equal(cred.publicKey.length, 128);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses a request for the wrong chain', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ows-node-cred-'));
    try {
      createCredential('c', 'midnight', null, 'pw', dir);
      assert.throws(() => signWithCredential('c', 'evm', withdrawUnshielded(), 'pw', dir));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('createApiKey accepts credentialIds and still works without them', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ows-node-cred-'));
    try {
      const wallet = createWallet('w', 'pw', 12, dir);
      const cred = createCredential('c', 'midnight', null, 'pw', dir);
      const plain = createApiKey('plain', [wallet.id], [], 'pw', null, dir);
      assert.ok(plain.token.startsWith('ows_key_'));
      const key = createApiKey('with-cred', [wallet.id], [], 'pw', null, dir, [cred.id]);
      const sig = signWithCredential('c', 'midnight', withdrawUnshielded(), key.token, dir);
      assert.equal(sig.pk, cred.publicKey);
      assert.match(sig.sigR, /^[0-9a-f]{128}$/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('listApiKeys returns no encrypted copies for a key holding a credential', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ows-node-cred-'));
    try {
      const wallet = createWallet('w', 'pw', 12, dir);
      const cred = createCredential('c', 'midnight', null, 'pw', dir);
      createApiKey('with-cred', [wallet.id], [], 'pw', null, dir, [cred.id]);
      const [listed] = listApiKeys(dir);
      assert.deepEqual(listed.credential_ids, [cred.id]);
      assert.equal('wallet_secrets' in listed, false);
      assert.equal('credential_secrets' in listed, false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('writes the same audit records for credentials as the CLI', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ows-node-cred-'));
    try {
      const cred = createCredential('c', 'midnight', null, 'pw', dir);
      signWithCredential('c', 'midnight:preview', withdrawUnshielded(), 'pw', dir);
      const key = createApiKey('agent', [], [], 'pw', null, dir, [cred.id]);
      revokeApiKey(key.id, dir);
      deleteCredential('c', dir);
      const log = readFileSync(join(dir, 'logs', 'audit.jsonl'), 'utf8')
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));
      assert.deepEqual(log.map((r) => r.operation), [
        'credential_created',
        'credential_signed',
        'create_api_key',
        'revoke_api_key',
        'credential_deleted',
      ]);
      assert.equal(log[1].chain_id, 'midnight:preview');
      assert.match(log[1].details, new RegExp(`^credential_id=${cred.id}, .*actor=owner, outcome=allowed$`));
      assert.equal(log.some((r) => 'wallet_id' in r), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('does not echo a secret passed in the scheme slot', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ows-node-cred-'));
    const secret = '0123456789abcdef0123456789abcdef';
    try {
      assert.throws(
        () => createCredential('c', 'midnight', secret, 'pw', dir),
        (e) => !e.message.includes(secret),
      );
      assert.throws(
        () => importCredential('c', 'midnight', 'jubjub', secret, 'pw', dir),
        (e) => !e.message.includes(secret),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
