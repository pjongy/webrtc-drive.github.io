# Vendored files

Third-party code served as part of the app. Each file comes from the project's official npm package (whose integrity is pinned by npm), committed without changes to its code. `tests/vendor.test.js` recomputes the SHA-256 of every file listed here and fails on a mismatch or an unlisted file. License texts are in the `LICENSE-*.txt` files next to them.

| File | Project | Version | Source | License | SHA-256 |
| --- | --- | --- | --- | --- | --- |
| `noble-crypto-2.4.0.js` | [@noble/curves](https://github.com/paulmillr/noble-curves), [@noble/hashes](https://github.com/paulmillr/noble-hashes), [@noble/ciphers](https://github.com/paulmillr/noble-ciphers) | 2.4.0 each | npm `@noble/curves@2.4.0`, `@noble/hashes@2.4.0`, `@noble/ciphers@2.4.0`; the `ristretto255`, `ristretto255_hasher`, `sha256`, `sha512`, `hkdf`, and `gcm` exports bundled into one ES module by `npm run vendor:noble` (esbuild, no minification). `npm run vendor:noble -- --check` verifies the committed file matches a fresh build | MIT | `1d1b2f87d6dfbe04667541f7076543907cc9a827f505fd13b32b0c58ceade6e7` |
| `qrcode-generator-2.0.4.mjs` | [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) | 2.0.4 | npm `qrcode-generator@2.0.4`, `dist/qrcode.mjs`, unmodified | MIT | `ea91d7118a5395289170da848b7c6758b996163bfbccf312591ab65a4911b7c0` |
| `jsQR-1.4.0.js` | [jsQR](https://github.com/cozmo/jsQR) | 1.4.0 | npm `jsqr@1.4.0`, `dist/jsQR.js`, unmodified. A classic script that defines `self.jsQR`; loaded only when `BarcodeDetector` is unavailable | Apache-2.0 | `bc40c8a15196236b2314db0856f72ca0b49980cd5413b8c852a7349f5fee0859` |

## Why the noble libraries are bundled here

noble-curves published standalone release files only up to 2.0.0, and that file does not expose `ristretto255_hasher.deriveToCurve` (RFC 9496 element derivation), which CPace needs. Hashing, HKDF, and AES-GCM also come from noble rather than `crypto.subtle`, because `crypto.subtle` exists only on secure (https or localhost) pages and the app must also work over plain http. So `scripts/vendor-noble.mjs` bundles the official 2.4.0 npm package sources, exactly as published, into one ES module. Both the inputs (npm integrity hashes in `package-lock.json`) and the output (SHA-256 above) are pinned.

## Updating a file

1. Bump the exact version in `package.json` devDependencies (for noble) or download the new npm tarball (for the QR libraries).
2. Replace the file, keeping the `<name>-<version>` file name, and update the import or script path in `site/`.
3. Update this table, including the SHA-256 (`sha256sum site/vendor/<file>`), and the license file if it changed.
4. Run `npm run check` and the E2E tests.
