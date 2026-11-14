//! Release checking, downloading, installing and self-updating for the Craft App Suite and ArtCraft Launcher.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]

pub mod app;
pub mod desktop_entry;
pub mod detect;
pub mod distro;
mod folders;
pub mod http;
pub mod install;
pub mod manifest;
pub mod msi_context;
mod msi_copy;
mod msi_migrate;
pub mod packages;
pub mod paths;
pub mod pins;
pub mod platform;
#[cfg(windows)]
pub mod portable;
pub mod process;
pub mod protocol;
pub mod proxy;
pub mod queue;
pub mod release;
pub mod self_update;
pub mod signed;
pub mod source;
pub mod status;
pub mod suite;
pub mod time;
pub mod version;

#[cfg(feature = "egui")]
pub mod dialog;
#[cfg(feature = "egui")]
pub mod updater;

pub use app::App;
pub use http::{Http, Stop};
pub use paths::Paths;
pub use platform::{Arch, Os, PackageKind, Platform, pick_asset};
pub use protocol::{InstallLocations, JobPhase, LatestRelease, Source};
pub use release::{Asset, Release, parse_github_release, parse_github_release_list};
pub use status::{InstallSource, Installed};
pub use suite::SUITE;
pub use time::parse_rfc3339;
pub use version::{Version, is_newer, parse as parse_version};

#[cfg(feature = "egui")]
pub use dialog::{CheckResultDialog, CheckResultResponse, StartupPrompt, StartupPromptResponse};

/// Checks for an update against GitHub releases for the given app.
pub fn check_for_update(app: &App, http: &Http, current_version: &str) -> Result<Option<Release>, String> {
    let version = self_update::current_version(app, current_version).map(|v| v.to_string());
    let current_version = version.as_deref().unwrap_or(current_version);
    let url = format!("https://api.github.com/repos/{}/releases?per_page=30", app.repo);
    match http.get_api(&url, None)? {
        crate::http::Fetched::Body { text, .. } => offered_release(app, http, &text, app.repo, current_version),
        crate::http::Fetched::RateLimited { .. } => Err("GitHub's request limit was reached".into()),
        crate::http::Fetched::NotModified | crate::http::Fetched::NotFound => Ok(None),
    }
}

/// Unix seconds now.
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// The release in GitHub's release list `json` to offer a copy running `current_version`, if any:
/// the latest published release, when [`version::offers_update`] says so. With signing keys set:
/// the latest of those whose checksum list is signed ([`signed::newest_signed`]).
fn offered_release(app: &App, http: &Http, json: &str, repo: &str, current_version: &str) -> Result<Option<Release>, String> {
    offer(app, http, crate::release::parse_github_release_candidates(json, repo)?, current_version)
}

/// The newest of `candidates` (newest first) to offer a copy running `current_version`.
fn offer(app: &App, http: &Http, candidates: Vec<Release>, current_version: &str) -> Result<Option<Release>, String> {
    let running = crate::version::parse(current_version);
    let newer = candidates
        .into_iter()
        .filter(|release| release.version.as_ref().zip(running.as_ref()).is_some_and(|(rel_v, cur_v)| crate::version::offers_update(rel_v, cur_v)))
        .collect();
    signed::newest_signed(app, newer, http)
}

#[cfg(test)]
pub(crate) const TEST_AGENT: &str = "ArtCraft-Launcher-Test/0.0";

#[cfg(test)]
mod offer_tests {
    use super::{offer, offered_release};
    use crate::signed::tests::{Paths, asked, serve_files};
    use crate::{App, Asset, Http, Release};

    const REPO: &str = "storytold/photocraft";
    const LIST: &str = r#"[{"tag_name":"v0.17.0","prerelease":false,"draft":false,"assets":[]},
        {"tag_name":"v0.16.4","prerelease":false,"draft":false,"assets":[]}]"#;

    fn offered(running: &str) -> Option<String> {
        let (app, http) = (App::new("photocraft", "PhotoCraft", "test", REPO), Http::new(crate::TEST_AGENT).unwrap());
        offered_release(&app, &http, LIST, REPO, running).unwrap().map(|release| release.tag)
    }

    type Requests = Paths;

    fn key_pair() -> minisign::KeyPair {
        minisign::KeyPair::generate_unencrypted_keypair().unwrap()
    }

    fn keyed(kp: &minisign::KeyPair) -> App {
        App { signing_keys: Box::leak(kp.pk.to_base64().into_boxed_str()), ..App::new("photocraft", "PhotoCraft", "test", REPO) }
    }

    /// The checksum list of a release of version `label`.
    fn list_for(label: &str) -> String {
        format!("{}  photocraft-{label}-windows-x64.msi\n", "a".repeat(64))
    }

    /// `release` with `list` and its signature by `signer` (`None`: HTTP 500) served from this
    /// machine; the paths asked for.
    fn served_list(release: Release, list: &str, signer: Option<&minisign::KeyPair>) -> (Release, Requests) {
        served_bytes(release, Some(list.as_bytes().to_vec()), signer.map(|s| sign(s, list).into_bytes()))
    }

    fn sign(signer: &minisign::KeyPair, list: &str) -> String {
        minisign::sign(Some(&signer.pk), &signer.sk, list.as_bytes(), None, None).unwrap().into_string()
    }

    /// `release` with the bytes `list` and `signature` (`None`: HTTP 500) served from this
    /// machine; the paths asked for.
    fn served_bytes(mut release: Release, list: Option<Vec<u8>>, signature: Option<Vec<u8>>) -> (Release, Requests) {
        let (base, requests) = serve_files(vec![("/SHA256SUMS.txt", list), ("/SHA256SUMS.txt.minisig", signature)]);
        for asset in &mut release.assets {
            if let Some(name) = ["SHA256SUMS.txt", "SHA256SUMS.txt.minisig"].iter().find(|n| **n == asset.name) {
                asset.url = format!("{base}/{name}");
            }
        }
        (release, requests)
    }

    /// `release` with its own list, signed by `signer`.
    fn served(release: Release, signer: &minisign::KeyPair) -> (Release, Requests) {
        let list = list_for(&release.version_label());
        served_list(release, &list, Some(signer))
    }

    fn release(tag: &str, signer: &minisign::KeyPair) -> (Release, Requests) {
        served(bare(tag), signer)
    }

    fn bare(tag: &str) -> Release {
        let assets = ["SHA256SUMS.txt", "SHA256SUMS.txt.minisig"].map(|name| Asset { name: name.into(), ..Asset::default() }).to_vec();
        Release { tag: tag.into(), version: crate::version::parse(tag), assets, ..Release::default() }
    }

    fn lists_fetched(requests: &[Requests]) -> usize {
        requests.iter().map(|r| asked(r, "/SHA256SUMS.txt")).sum()
    }

    #[test]
    fn a_failed_fetch_fails_the_check_and_offers_nothing_older() {
        let ours = key_pair();
        // The newest release's signature answers HTTP 500.
        let (newest, _) = served_list(bare("v1.0.5"), &list_for("1.0.5"), None);
        let (older, _) = release("v1.0.4", &ours);
        let http = Http::new(crate::TEST_AGENT).unwrap();
        let result = offer(&keyed(&ours), &http, vec![newest, older], "1.0.3");
        assert!(result.as_ref().is_err_and(|e| e.contains("couldn't fetch")), "{result:?}");
    }

    /// Whoever uploads a release chooses the size of its files: a fake newest release whose
    /// signature or checksum list is over its cap is skipped like an unsigned one, so it can't
    /// block the signed release below it.
    #[test]
    fn an_oversized_signature_or_list_skips_the_release_for_the_signed_one_below() {
        let ours = key_pair();
        let http = Http::new(crate::TEST_AGENT).unwrap();
        // A valid signature with 5 KiB of padding (the cap is 4 KiB).
        let list = list_for("9.9.9");
        let mut padded = sign(&ours, &list).into_bytes();
        padded.extend(vec![b'\n'; 5 * 1024]);
        let (fake, fake_requests) = served_bytes(bare("v9.9.9"), Some(list.into_bytes()), Some(padded));
        let (real, _) = release("v1.0.4", &ours);
        assert_eq!(offer(&keyed(&ours), &http, vec![fake, real], "1.0.3").unwrap().map(|r| r.tag).as_deref(), Some("v1.0.4"));
        assert_eq!(asked(&fake_requests, "/SHA256SUMS.txt"), 0, "the list of a release whose signature is refused isn't fetched");
        // A validly signed list of 300 KiB (the cap is 256 KiB).
        let mut long = list_for("9.9.9");
        while long.len() < 300 * 1024 {
            long.push_str(&list_for("9.9.9"));
        }
        let (fake, _) = served_list(bare("v9.9.9"), &long, Some(&ours));
        let (real, _) = release("v1.0.4", &ours);
        assert_eq!(offer(&keyed(&ours), &http, vec![fake, real], "1.0.3").unwrap().map(|r| r.tag).as_deref(), Some("v1.0.4"));
    }

    /// A server error is no proof of a missing signature: the list answering HTTP 500 fails the
    /// check, as the signature answering 500 does.
    #[test]
    fn a_server_error_for_the_list_fails_the_check() {
        let ours = key_pair();
        let list = list_for("1.0.5");
        let (newest, _) = served_bytes(bare("v1.0.5"), None, Some(sign(&ours, &list).into_bytes()));
        let (older, _) = release("v1.0.4", &ours);
        let http = Http::new(crate::TEST_AGENT).unwrap();
        let result = offer(&keyed(&ours), &http, vec![newest, older], "1.0.3");
        assert!(result.as_ref().is_err_and(|e| e.contains("couldn't fetch")), "{result:?}");
    }

    #[test]
    fn a_replayed_signed_list_does_not_make_a_fake_release_signed() {
        let ours = key_pair();
        // A fake v9.9.9 carrying v1.0.4's real list and signature.
        let (fake, _) = served_list(bare("v9.9.9"), &list_for("1.0.4"), Some(&ours));
        let (real, _) = release("v1.0.4", &ours);
        let http = Http::new(crate::TEST_AGENT).unwrap();
        assert_eq!(offer(&keyed(&ours), &http, vec![fake, real], "1.0.3").unwrap().map(|r| r.tag).as_deref(), Some("v1.0.4"));
    }

    #[test]
    fn an_unsigned_newest_release_is_skipped_for_the_newest_signed_one() {
        let (ours, theirs) = (key_pair(), key_pair());
        let (fake, _) = release("v9.9.9", &theirs);
        let (real, _) = release("v1.0.4", &ours);
        let http = Http::new(crate::TEST_AGENT).unwrap();
        let offered = offer(&keyed(&ours), &http, vec![fake, real], "1.0.3").unwrap();
        assert_eq!(offered.map(|r| r.tag).as_deref(), Some("v1.0.4"));
    }

    #[test]
    fn only_the_five_newest_releases_are_looked_at() {
        let (ours, theirs) = (key_pair(), key_pair());
        let (mut candidates, mut requests): (Vec<Release>, Vec<Requests>) = (0..6).map(|i| release(&format!("v2.0.{}", 5 - i), &theirs)).unzip();
        let (signed, signed_requests) = release("v1.0.4", &ours);
        candidates.push(signed);
        requests.push(signed_requests);
        let http = Http::new(crate::TEST_AGENT).unwrap();
        assert_eq!(offer(&keyed(&ours), &http, candidates, "1.0.3").unwrap(), None);
        assert_eq!(lists_fetched(&requests), 5);
    }

    #[test]
    fn without_keys_the_newest_release_is_offered_and_no_list_is_fetched() {
        let kp = key_pair();
        let (newest, newest_requests) = release("v9.9.9", &kp);
        let (older, older_requests) = release("v1.0.4", &kp);
        let (app, http) = (App::new("photocraft", "PhotoCraft", "test", REPO), Http::new(crate::TEST_AGENT).unwrap());
        assert_eq!(offer(&app, &http, vec![newest, older], "1.0.3").unwrap().map(|r| r.tag).as_deref(), Some("v9.9.9"));
        assert_eq!(lists_fetched(&[newest_requests, older_requests]), 0);
    }

    #[test]
    fn a_release_known_only_from_its_checksums_follows_the_same_rule() {
        let (ours, theirs) = (key_pair(), key_pair());
        let sums = [("a".repeat(64), "photocraft-1.0.4-windows-x64.msi".to_string())];
        let from_sums = |tag: &str| crate::release::release_from_sums(REPO, tag, &sums);
        // It lists no signature: the check derives its address from the list's.
        assert!(from_sums("v1.0.4").signature_asset().is_none());
        let http = Http::new(crate::TEST_AGENT).unwrap();
        let (fake, fake_requests) = served(from_sums("v9.9.9"), &theirs);
        assert_eq!(offer(&keyed(&ours), &http, vec![fake], "1.0.3").unwrap(), None);
        assert_eq!(lists_fetched(&[fake_requests]), 1, "the list was read, and its signature refused");
        let (fake, _) = served(from_sums("v9.9.9"), &theirs);
        let (real, _) = served(from_sums("v1.0.4"), &ours);
        assert_eq!(offer(&keyed(&ours), &http, vec![fake, real], "1.0.3").unwrap().map(|r| r.tag).as_deref(), Some("v1.0.4"));
    }

    #[test]
    fn a_build_from_main_is_not_offered_the_release_it_already_contains() {
        assert_eq!(offered("0.17.0-integration.20261029.f5b3f123"), None);
        assert_eq!(offered("0.16.5-dev"), Some("v0.17.0".into()));
    }

    #[test]
    fn releases_and_release_candidates_are_offered_as_before() {
        assert_eq!(offered("0.17.0-rc.2"), Some("v0.17.0".into()));
        assert_eq!(offered("0.16.4"), Some("v0.17.0".into()));
        assert_eq!(offered("0.17.0"), None);
        assert_eq!(offered("not a version"), None);
    }
}
