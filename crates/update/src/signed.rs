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

/// Reads a key list, in these steps: a byte order mark at the start is an error; the text is split
/// on `\n`; one trailing `\r` is stripped from each line; spaces and tabs (nothing else) are
/// trimmed from both ends; a line that is then empty, or starts with `#`, is skipped; every other
/// line must be one minisign public key (base64), and one bad line makes the whole list an error.
/// A text with no key line gives no keys.
pub fn keys(text: &str) -> Result<Vec<PublicKey>, String> {
    if text.starts_with('\u{feff}') {
        return Err("the update keys start with a byte order mark".into());
    }
    text.split('\n')
        .enumerate()
        .map(|(n, line)| (n, line.strip_suffix('\r').unwrap_or(line).trim_matches([' ', '\t'])))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(n, line)| PublicKey::from_base64(line).map_err(|e| format!("line {} of the update keys isn't a minisign public key ({e})", n + 1)))
        .collect()
}

/// What [`check_release`] found out about a release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Checked {
    /// The app sets no signing keys; nothing was fetched.
    NoKeys,
    /// One of the app's keys signed the release's checksum list: its `(hash, name)` lines.
    Signed(Vec<(String, String)>),
    /// The release has no valid signature: it publishes no checksum list or no signature (a 404),
    /// the signature doesn't decode, no key accepts it, or the signed list isn't text.
    Unsigned,
}

/// Checks `release`'s checksum list against `app`'s signing keys. `Err` means it couldn't be found
/// out: a fetch of the signature or the list failed (no connection, a timeout, an HTTP error other
/// than 404, a file over its cap), or the app's key list is unreadable.
pub fn check_release(app: &App, release: &Release, http: &Http) -> Result<Checked, String> {
    let keys = keys(app.signing_keys).map_err(|e| {
        log::warn!("{}: {e}", app.name);
        NOT_SIGNED.to_string()
    })?;
    if keys.is_empty() {
        return Ok(Checked::NoKeys);
    }
    let Some(sums) = release.sums_asset() else { return Ok(Checked::Unsigned) };
    // A release known only from its checksum list doesn't list its signature: it sits beside the list.
    let signature_url = release.signature_asset().map_or_else(|| format!("{}.minisig", sums.url), |a| a.url.clone());
    let fetch = |url: &str, max: usize| http.get_bytes(url, max).map_err(|e| format!("couldn't fetch the release's checksums ({e}). Try again"));
    let Some(signature) = fetch(&signature_url, MAX_SIGNATURE)? else { return Ok(Checked::Unsigned) };
    let Some(signature) = std::str::from_utf8(&signature).ok().and_then(|text| Signature::decode(text).ok()) else { return Ok(Checked::Unsigned) };
    let Some(list) = fetch(&sums.url, MAX_SUMS)? else { return Ok(Checked::Unsigned) };
    if !keys.iter().any(|key| key.verify(&list, &signature, false).is_ok()) {
        return Ok(Checked::Unsigned);
    }
    Ok(std::str::from_utf8(&list).map_or(Checked::Unsigned, |text| Checked::Signed(release::parse_sha256sums(text))))
}

/// The checksum list of `release`, when one of `app`'s keys signed it. `Ok(None)`: the app sets no
/// keys, and nothing was fetched. `Err`: no valid signature, or it couldn't be found out.
pub fn verified_sums(app: &App, release: &Release, http: &Http) -> Result<Option<Vec<(String, String)>>, String> {
    match check_release(app, release, http)? {
        Checked::NoKeys => Ok(None),
        Checked::Signed(sums) => Ok(Some(sums)),
        Checked::Unsigned => Err(NOT_SIGNED.into()),
    }
}

/// The first of the [`MAX_CANDIDATES`] newest `candidates` (newest first) whose checksum list has
/// a valid signature and names a file of that release's version; a release without one is skipped
/// without a word. A check that fails (see [`check_release`]) fails the whole choice, so a network
/// hiccup never offers an older release. With no keys set: the first candidate, and nothing is
/// fetched.
pub fn newest_signed(app: &App, candidates: Vec<Release>, http: &Http) -> Result<Option<Release>, String> {
    if keys(app.signing_keys).map_err(|_| NOT_SIGNED)?.is_empty() {
        return Ok(candidates.into_iter().next());
    }
    for candidate in candidates.into_iter().take(MAX_CANDIDATES) {
        match check_release(app, &candidate, http)? {
            Checked::NoKeys => return Ok(Some(candidate)),
            Checked::Signed(sums) if names_its_version(app, &candidate, &sums) => return Ok(Some(candidate)),
            Checked::Signed(_) => log::info!("{}: skipping {}: its signed checksum list names no file of that version", app.name, candidate.tag),
            Checked::Unsigned => log::info!("{}: skipping {}: {NOT_SIGNED}", app.name, candidate.tag),
        }
    }
    Ok(None)
}

/// Whether the signed list `sums` names a file of `app` whose version is `release`'s: a list
/// copied from another release, with its signature, doesn't make this one signed.
fn names_its_version(app: &App, release: &Release, sums: &[(String, String)]) -> bool {
    let stems: Vec<&str> = app.stems().collect();
    release.version.as_ref().is_some_and(|version| {
        sums.iter().any(|(_, name)| {
            crate::platform::parse_asset_name(name, &stems).is_some_and(|parsed| crate::version::parse(&parsed.version).as_ref() == Some(version))
        })
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::http::tests::{Reply, serve};
    use crate::release::Asset;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    type Requests = Arc<Mutex<Vec<Option<String>>>>;
    pub(crate) type Paths = Arc<Mutex<Vec<String>>>;

    /// Serves `files` (path, body) over plain HTTP until the test ends: a body of `None` answers
    /// HTTP 500, and any other path 404. Records each path asked for.
    pub(crate) fn serve_files(files: Vec<(&'static str, Option<Vec<u8>>)>) -> (String, Paths) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen: Paths = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                let _ = reader.read_line(&mut first);
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                }
                let path = first.split_whitespace().nth(1).unwrap_or_default().to_string();
                log.lock().unwrap().push(path.clone());
                let close = "Connection: close\r\n\r\n";
                let _ = match files.iter().find(|(p, _)| *p == path) {
                    Some((_, Some(body))) => {
                        write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{close}", body.len()).and_then(|()| stream.write_all(body))
                    }
                    Some((_, None)) => write!(stream, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n{close}"),
                    None => write!(stream, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n{close}"),
                };
            }
        });
        (base, seen)
    }

    /// How often `path` was asked for.
    pub(crate) fn asked(paths: &Paths, path: &str) -> usize {
        paths.lock().unwrap().iter().filter(|p| *p == path).count()
    }

    /// A release `tag` whose `SHA256SUMS.txt` (and, with `signature_asset`, its listed
    /// `SHA256SUMS.txt.minisig`) sit under `base`.
    pub(crate) fn release_at(base: &str, tag: &str, signature_asset: bool) -> Release {
        let mut assets = vec![Asset { name: "SHA256SUMS.txt".into(), url: format!("{base}/SHA256SUMS.txt"), ..Asset::default() }];
        if signature_asset {
            assets.push(Asset { name: "SHA256SUMS.txt.minisig".into(), url: format!("{base}/SHA256SUMS.txt.minisig"), ..Asset::default() });
        }
        Release { tag: tag.into(), version: crate::version::parse(tag), assets, ..Release::default() }
    }

    /// A release whose list and signature `serve_files` serves (`None`: HTTP 500; a missing
    /// entry: 404); and the paths asked for.
    fn files(list: Option<Vec<u8>>, sig: Option<Option<Vec<u8>>>, signature_asset: bool) -> (Release, Paths) {
        let mut files = vec![("/SHA256SUMS.txt", list)];
        if let Some(sig) = sig {
            files.push(("/SHA256SUMS.txt.minisig", sig));
        }
        let (base, paths) = serve_files(files);
        (release_at(&base, "v1.0.4", signature_asset), paths)
    }

    #[test]
    fn a_missing_bad_or_foreign_signature_means_unsigned() {
        let (kp, other) = (key_pair(), key_pair());
        let app = app(&kp.pk.to_base64());
        let good = || Some(Some(sign(&kp, list().as_bytes()).into_bytes()));
        let list = || Some(list().into_bytes());
        // No signature at the listed asset, or at the URL derived from the list's.
        for signature_asset in [true, false] {
            let (release, _) = files(list(), None, signature_asset);
            assert_eq!(check_release(&app, &release, &http()), Ok(Checked::Unsigned));
        }
        let (release, _) = files(list(), Some(Some(b"not a signature".to_vec())), true);
        assert_eq!(check_release(&app, &release, &http()), Ok(Checked::Unsigned));
        let (release, _) = files(list(), Some(Some(sign(&other, list().unwrap().as_slice()).into_bytes())), true);
        assert_eq!(check_release(&app, &release, &http()), Ok(Checked::Unsigned));
        // A list that isn't text, though validly signed.
        let bytes = vec![0xff, 0xfe, 0x00, 0x41];
        let (release, _) = files(Some(bytes.clone()), Some(Some(sign(&kp, &bytes).into_bytes())), true);
        assert_eq!(check_release(&app, &release, &http()), Ok(Checked::Unsigned));
        // The good one, through the listed asset and through the derived URL.
        for signature_asset in [true, false] {
            let (release, _) = files(list(), good(), signature_asset);
            assert_eq!(check_release(&app, &release, &http()), Ok(Checked::Signed(pairs())));
        }
        assert_eq!(check_release(&self::app(""), &files(list(), good(), true).0, &http()), Ok(Checked::NoKeys));
    }

    #[test]
    fn a_failed_fetch_is_an_error_not_unsigned() {
        let kp = key_pair();
        let app = app(&kp.pk.to_base64());
        let good = Some(sign(&kp, list().as_bytes()).into_bytes());
        // The signature answers HTTP 500; then the list does.
        let (release, _) = files(Some(list().into_bytes()), Some(None), true);
        assert!(check_release(&app, &release, &http()).is_err_and(|e| e.contains("couldn't fetch")));
        let (release, _) = files(None, Some(good), true);
        assert!(check_release(&app, &release, &http()).is_err_and(|e| e.contains("couldn't fetch")));
        // Nothing listens there.
        let mut release = files(Some(list().into_bytes()), None, true).0;
        for asset in &mut release.assets {
            asset.url = "http://127.0.0.1:9/SHA256SUMS.txt".into();
        }
        assert!(check_release(&app, &release, &http()).is_err_and(|e| e.contains("couldn't fetch")));
    }

    #[test]
    fn a_release_that_lists_no_signature_is_checked_through_the_derived_address() {
        let kp = key_pair();
        let (release, paths) = files(Some(list().into_bytes()), Some(Some(sign(&kp, list().as_bytes()).into_bytes())), false);
        assert!(release.signature_asset().is_none());
        assert_eq!(verified_sums(&app(&kp.pk.to_base64()), &release, &http()), Ok(Some(pairs())));
        assert_eq!(asked(&paths, "/SHA256SUMS.txt.minisig"), 1);
    }

    #[test]
    fn the_key_list_follows_the_format_step_by_step() {
        let kp = key_pair();
        let key = kp.pk.to_base64();
        // A byte order mark.
        assert!(keys(&format!("\u{feff}{key}\n")).is_err_and(|e| e.contains("byte order mark")));
        assert!(keys("\u{feff}# comment\n").is_err_and(|e| e.contains("byte order mark")));
        // A line of only a no-break space is not empty.
        assert!(keys(&format!("{key}\n\u{a0}\n")).is_err());
        // The carriage return goes only at the very end of a line.
        assert!(keys(&format!("{key}\r \n")).is_err());
        // CRLF line ends, spaces and tabs round a key, an indented comment.
        assert_eq!(keys(&format!("# keys\r\n \t{key}\t \r\n  \t# indented comment\r\n\r\n")).map(|k| k.len()), Ok(1));
        // Comments and empty lines only: no keys.
        assert_eq!(keys("# one\n\n  # two\r\n\t\n").map(|k| k.len()), Ok(0));
    }

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
