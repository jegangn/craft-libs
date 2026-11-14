//! Release signatures: a minisign signature over a release's `SHA256SUMS.txt`.
//!
//! An app that sets [`App::signing_keys`] takes every SHA-256 from a checksum list that one of
//! those keys signed, never from GitHub's per-file digest, and skips a release without a valid
//! signature. An app with no keys works exactly as before: nothing here fetches anything for it.

use minisign_verify::{PublicKey, Signature};

use crate::app::App;
use crate::http::Http;
use crate::release::{self, Release};

/// The largest signature file read: a minisign signature is a few hundred bytes.
const MAX_SIGNATURE: usize = 4 * 1024;
/// The largest checksum list read.
const MAX_SUMS: usize = 256 * 1024;
/// How many of the newest releases [`newest_signed`] looks at.
const MAX_CANDIDATES: usize = 5;

/// The refusal for a release whose checksum list has no valid signature.
const NOT_SIGNED: &str =
    "the release's checksum list has no valid signature, so it can't be verified and wasn't installed. Try again later, or report it on GitHub.";

/// Reads a key list: one minisign public key (base64) on a line; a line that starts with `#` is a
/// comment, and empty lines are skipped. An empty text gives no keys.
pub fn keys(text: &str) -> Result<Vec<PublicKey>, String> {
    text.lines()
        .enumerate()
        .map(|(n, line)| (n, line.trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(n, line)| PublicKey::from_base64(line).map_err(|e| format!("line {} of the update keys isn't a minisign public key ({e})", n + 1)))
        .collect()
}

/// The checksum list of `release`, when one of `app`'s keys signed it. `Ok(None)`: the app sets no
/// keys, and nothing was fetched. `Err`: no valid signature (or it couldn't be fetched).
pub fn verified_sums(app: &App, release: &Release, http: &Http) -> Result<Option<Vec<(String, String)>>, String> {
    let keys = keys(app.signing_keys).map_err(|e| {
        log::warn!("{}: {e}", app.name);
        NOT_SIGNED.to_string()
    })?;
    if keys.is_empty() {
        return Ok(None);
    }
    let (Some(sums), Some(signature)) = (release.sums_asset(), release.signature_asset()) else { return Err(NOT_SIGNED.into()) };
    let fetch = |url: &str, max: usize| http.get_bytes(url, max).map_err(|e| format!("couldn't fetch the release's checksums ({e}). Try again"));
    let Some(signature) = fetch(&signature.url, MAX_SIGNATURE)? else { return Err(NOT_SIGNED.into()) };
    let signature = std::str::from_utf8(&signature).ok().and_then(|text| Signature::decode(text).ok()).ok_or(NOT_SIGNED)?;
    let Some(list) = fetch(&sums.url, MAX_SUMS)? else { return Err(NOT_SIGNED.into()) };
    if !keys.iter().any(|key| key.verify(&list, &signature, false).is_ok()) {
        return Err(NOT_SIGNED.into());
    }
    let text = std::str::from_utf8(&list).map_err(|_| NOT_SIGNED)?;
    Ok(Some(release::parse_sha256sums(text)))
}

/// The first of the [`MAX_CANDIDATES`] newest `candidates` (newest first) whose checksum list has
/// a valid signature; a release without one is skipped without a word. With no keys set: the first
/// candidate, and nothing is fetched.
pub fn newest_signed(app: &App, candidates: Vec<Release>, http: &Http) -> Result<Option<Release>, String> {
    if keys(app.signing_keys).map_err(|_| NOT_SIGNED)?.is_empty() {
        return Ok(candidates.into_iter().next());
    }
    for candidate in candidates.into_iter().take(MAX_CANDIDATES) {
        match verified_sums(app, &candidate, http) {
            Ok(_) => return Ok(Some(candidate)),
            Err(e) => log::info!("{}: skipping {}: {e}", app.name, candidate.tag),
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::tests::{Reply, serve};
    use crate::release::Asset;
    use std::sync::{Arc, Mutex};

    type Requests = Arc<Mutex<Vec<Option<String>>>>;

    const HASH_A: &str = "8a5edab282632443219e051e4ade2d1d5bbc671c781051bf1437897cbdfea0f1";
    const HASH_B: &str = "0b5edab282632443219e051e4ade2d1d5bbc671c781051bf1437897cbdfea0f2";

    fn list() -> String {
        format!("{HASH_A}  wordcraft-1.0.4-windows-x64.msi\n{HASH_B}  wordcraft-1.0.4-windows-x64-portable.zip\n")
    }

    fn pairs() -> Vec<(String, String)> {
        vec![
            (HASH_A.to_string(), "wordcraft-1.0.4-windows-x64.msi".to_string()),
            (HASH_B.to_string(), "wordcraft-1.0.4-windows-x64-portable.zip".to_string()),
        ]
    }

    fn key_pair() -> minisign::KeyPair {
        minisign::KeyPair::generate_unencrypted_keypair().unwrap()
    }

    fn sign(kp: &minisign::KeyPair, data: &[u8]) -> String {
        minisign::sign(Some(&kp.pk), &kp.sk, data, None, None).unwrap().into_string()
    }

    fn app(keys: &str) -> App {
        App { signing_keys: Box::leak(keys.to_string().into_boxed_str()), ..App::new("wordcraft", "WordCraft", "test", "storytold/wordcraft") }
    }

    /// A release whose `SHA256SUMS.txt` is `list` and whose signature file is `sig`, each served
    /// once; and what each server was asked.
    fn served(list: &[u8], sig: &[u8]) -> (Release, Requests, Requests) {
        let (list_url, list_requests) = serve(list.to_vec(), vec![Reply::Full]);
        let (sig_url, sig_requests) = serve(sig.to_vec(), vec![Reply::Full]);
        let assets = vec![
            Asset { name: "SHA256SUMS.txt".into(), size: 0, url: list_url, sha256: None },
            Asset { name: "SHA256SUMS.txt.minisig".into(), size: 0, url: sig_url, sha256: None },
        ];
        (Release { tag: "v1.0.4".into(), assets, ..Release::default() }, list_requests, sig_requests)
    }

    fn http() -> Http {
        Http::new(crate::TEST_AGENT).unwrap()
    }

    #[test]
    fn the_right_key_gives_the_signed_checksums() {
        let kp = key_pair();
        let (release, _, _) = served(list().as_bytes(), sign(&kp, list().as_bytes()).as_bytes());
        assert_eq!(verified_sums(&app(&kp.pk.to_base64()), &release, &http()), Ok(Some(pairs())));
    }

    #[test]
    fn a_wrong_key_alone_is_refused() {
        let (kp, other) = (key_pair(), key_pair());
        let (release, _, _) = served(list().as_bytes(), sign(&kp, list().as_bytes()).as_bytes());
        assert_eq!(verified_sums(&app(&other.pk.to_base64()), &release, &http()), Err(NOT_SIGNED.into()));
    }

    #[test]
    fn any_of_several_keys_may_sign() {
        let (kp, other) = (key_pair(), key_pair());
        let (release, _, _) = served(list().as_bytes(), sign(&kp, list().as_bytes()).as_bytes());
        let keys = format!("{}\n{}\n", other.pk.to_base64(), kp.pk.to_base64());
        assert_eq!(verified_sums(&app(&keys), &release, &http()), Ok(Some(pairs())));
    }

    #[test]
    fn one_changed_byte_in_the_list_is_refused() {
        let kp = key_pair();
        let signature = sign(&kp, list().as_bytes());
        let mut changed = list().into_bytes();
        changed[3] = if changed[3] == b'0' { b'1' } else { b'0' };
        let (release, _, _) = served(&changed, signature.as_bytes());
        assert_eq!(verified_sums(&app(&kp.pk.to_base64()), &release, &http()), Err(NOT_SIGNED.into()));
    }

    #[test]
    fn a_key_line_that_is_not_base64_is_refused() {
        assert!(keys("not a key at all!").is_err());
        let kp = key_pair();
        assert!(keys(&format!("{}\n@@@@\n", kp.pk.to_base64())).is_err());
    }

    #[test]
    fn comments_and_empty_lines_are_skipped() {
        let kp = key_pair();
        let text = format!("# TellMeCAD update key\n\n{}\n   \n# an old key, retired\n", kp.pk.to_base64());
        let read = keys(&text).unwrap();
        assert_eq!(read.len(), 1);
        assert_eq!(keys("").unwrap().len(), 0);
        assert_eq!(keys("# only a comment\n").unwrap().len(), 0);
    }

    #[test]
    fn without_keys_nothing_is_checked_or_fetched() {
        let (release, list_requests, sig_requests) = served(list().as_bytes(), b"not a signature");
        assert_eq!(verified_sums(&app(""), &release, &http()), Ok(None));
        assert!(list_requests.lock().unwrap().is_empty() && sig_requests.lock().unwrap().is_empty());
    }

    #[test]
    fn an_oversized_signature_or_list_is_refused_before_it_is_read() {
        let kp = key_pair();
        // A valid signature with 5 KiB of padding: the decoder would read only its first lines.
        let padded = format!("{}{}", sign(&kp, list().as_bytes()), "\n".repeat(5 * 1024));
        let (release, _, _) = served(list().as_bytes(), padded.as_bytes());
        let err = verified_sums(&app(&kp.pk.to_base64()), &release, &http()).unwrap_err();
        assert!(err.contains("more than"), "{err}");
        // A list of 300 KiB, validly signed.
        let mut long = list();
        while long.len() < 300 * 1024 {
            long.push_str(&list());
        }
        let (release, _, _) = served(long.as_bytes(), sign(&kp, long.as_bytes()).as_bytes());
        let err = verified_sums(&app(&kp.pk.to_base64()), &release, &http()).unwrap_err();
        assert!(err.contains("more than"), "{err}");
    }
}
