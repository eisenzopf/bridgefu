//! Conformance gate for every built-in recipe.
//!
//! Bridgefu's product boundary is the recipe: a supported pairing of one
//! signaling/media source with one destination. Only
//! `vapi-amazon-connect-screen-pop` has ever been exercised against a live
//! deployment, so the other three could regress silently. This test compiles
//! every built-in against its own published example values and pins the result.
//!
//! Two layers:
//!
//! 1. In-process, through `bridgefu::recipes`, covering the catalog, the
//!    compiler, input completeness, and the negative cases.
//! 2. Through the `bridgefu` binary, covering the exact CLI and `--config`
//!    entry points that `bridgefu-vapi-awsconnect` drives when it builds and
//!    qualifies a customer AMI.
//!
//! Deliberately dependency-free: everything here uses crates already in the
//! locked graph. `bridgefu-vapi-awsconnect` SHA-256s this repository's
//! `Cargo.lock` as an AMI build input, so a new dev-dependency would break the
//! downstream pin.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use bridgefu::recipes::{RecipeCatalog, RecipeSelector, RecipeSource, RecipeSupport};
use serde_yaml::Value;

/// One built-in recipe and the example values published alongside it.
struct Builtin {
    /// Directory under `recipes/`, which is also the manifest's metadata name.
    name: &'static str,
    /// Source transport, for failure messages that say what actually broke.
    source: &'static str,
    /// Destination transport.
    destination: &'static str,
}

/// Every recipe embedded by `src/recipes/catalog.rs`. Adding a built-in without
/// adding it here fails `catalog_matches_this_table`.
const BUILTINS: &[Builtin] = &[
    Builtin {
        name: "vapi-amazon-connect-screen-pop",
        source: "Vapi SIP transfer",
        destination: "Amazon Connect WebRTC",
    },
    Builtin {
        name: "webrtc-amazon-connect-bridge",
        source: "browser WebRTC",
        destination: "Amazon Connect WebRTC",
    },
    Builtin {
        name: "sip-webrtc-bridge",
        source: "SIP/RTP or SIPS/SRTP",
        destination: "interactive WebRTC",
    },
    Builtin {
        name: "webrtc-sip-bridge",
        source: "interactive WebRTC",
        destination: "SIP/RTP or SIPS/SRTP",
    },
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

impl Builtin {
    fn selector(&self) -> String {
        format!("builtin:{}@1", self.name)
    }

    fn values_path(&self) -> PathBuf {
        repo_root()
            .join("recipes")
            .join(self.name)
            .join("values.example.yaml")
    }

    /// The recipe's published example values, as the compiler wants them.
    fn example_values(&self) -> BTreeMap<String, Value> {
        let path = self.values_path();
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} is unreadable: {error}", path.display()));
        serde_yaml::from_str(&raw)
            .unwrap_or_else(|error| panic!("{} is not a YAML mapping: {error}", path.display()))
    }
}

// ---------------------------------------------------------------------------
// Layer 1 — in-process
// ---------------------------------------------------------------------------

#[test]
fn catalog_matches_this_table() {
    let catalog = RecipeCatalog::builtin().expect("the built-in catalog must construct");
    let embedded: Vec<String> = catalog
        .iter()
        .map(|package| package.manifest().metadata.name.clone())
        .collect();

    let mut expected: Vec<String> = BUILTINS.iter().map(|b| b.name.to_owned()).collect();
    let mut found = embedded.clone();
    expected.sort();
    found.sort();

    assert_eq!(
        found, expected,
        "the embedded catalog and this test's table disagree. A recipe was \
         added or removed in src/recipes/catalog.rs without updating BUILTINS, \
         so the new recipe has no conformance coverage."
    );
}

#[test]
fn every_builtin_resolves_as_an_embedded_package() {
    let catalog = RecipeCatalog::builtin().expect("the built-in catalog must construct");

    for builtin in BUILTINS {
        let selector = builtin.selector();

        RecipeSelector::parse(&selector)
            .unwrap_or_else(|error| panic!("{selector} is not a valid selector: {error:?}"));

        let package = catalog
            .resolve(&selector)
            .unwrap_or_else(|error| panic!("{selector} does not resolve: {error:?}"));

        assert!(
            matches!(package.source(), RecipeSource::Builtin),
            "{selector} ({} -> {}) resolved to an external package; built-ins \
             must come from the compiled-in manifest, never the filesystem",
            builtin.source,
            builtin.destination,
        );

        assert_eq!(
            package.manifest().metadata.version,
            1,
            "{selector} is not version 1; the selector in this table is stale",
        );

        // A built-in may never claim `supported` without the retained live
        // evidence and runbooks that docs/recipes.md requires for that tier.
        assert_ne!(
            package.effective_support(),
            RecipeSupport::Supported,
            "{selector} claims the `supported` tier. That tier requires \
             retained hermetic and live evidence plus runbooks; promote it \
             deliberately, not by editing a manifest.",
        );
    }
}

#[test]
fn every_builtin_compiles_against_its_published_example() {
    let catalog = RecipeCatalog::builtin().expect("the built-in catalog must construct");

    for builtin in BUILTINS {
        let selector = builtin.selector();
        let package = catalog.resolve(&selector).expect("selector resolves");

        let compiled = package
            .compile(&builtin.example_values())
            .unwrap_or_else(|error| {
                panic!(
                    "{selector} ({} -> {}) does not compile against its own \
                     {}: {error:?}. The published example and the manifest \
                     have drifted apart.",
                    builtin.source,
                    builtin.destination,
                    builtin.values_path().display(),
                )
            });

        assert_eq!(compiled.name, builtin.name);
        assert_eq!(compiled.version, 1);
        assert!(
            !compiled.spec.bridges.is_empty(),
            "{selector} compiled to zero bridges; a recipe with no bridge \
             cannot carry a call",
        );
        assert!(
            !compiled.fingerprint.is_empty(),
            "{selector} produced an empty fingerprint",
        );
    }
}

#[test]
fn compilation_is_deterministic() {
    let catalog = RecipeCatalog::builtin().expect("the built-in catalog must construct");

    for builtin in BUILTINS {
        let package = catalog.resolve(&builtin.selector()).expect("resolves");
        let values = builtin.example_values();

        let first = package.compile(&values).expect("compiles").fingerprint;
        let second = package.compile(&values).expect("compiles").fingerprint;

        assert_eq!(
            first,
            second,
            "{} produced two different fingerprints for identical input. The \
             fingerprint is the deployment's identity; it must not depend on \
             map ordering, hashing, time, or any other ambient state.",
            builtin.selector(),
        );
    }
}

#[test]
fn fingerprints_match_the_recorded_goldens() {
    let path = repo_root()
        .join("tests")
        .join("fixtures")
        .join("recipe-fingerprints.json");
    let goldens: BTreeMap<String, String> = serde_json::from_str(
        &std::fs::read_to_string(&path).expect("the golden fingerprint file must exist"),
    )
    .expect("the golden fingerprint file must be a JSON object of strings");

    let catalog = RecipeCatalog::builtin().expect("the built-in catalog must construct");

    for builtin in BUILTINS {
        let key = format!("{}@1", builtin.name);
        let expected = goldens
            .get(&key)
            .unwrap_or_else(|| panic!("{key} has no recorded fingerprint in {}", path.display()));

        let compiled = catalog
            .resolve(&builtin.selector())
            .expect("resolves")
            .compile(&builtin.example_values())
            .expect("compiles");

        assert_eq!(
            &compiled.fingerprint,
            expected,
            "\n{key} now compiles to a different bridge graph.\n  \
             recorded: {expected}\n  observed: {}\n\
             If the manifest change was deliberate, update {} in this same \
             commit. If it was not, the recipe was edited by accident and \
             customers would deploy something different.\n",
            compiled.fingerprint,
            path.display(),
        );
    }
}

#[test]
fn published_examples_supply_every_required_input() {
    let catalog = RecipeCatalog::builtin().expect("the built-in catalog must construct");

    for builtin in BUILTINS {
        let package = catalog.resolve(&builtin.selector()).expect("resolves");
        let manifest = package.manifest();
        let values = builtin.example_values();

        for (name, definition) in &manifest.inputs {
            if definition.required && definition.default.is_none() {
                assert!(
                    values.contains_key(name),
                    "{} declares required input {name:?} but its \
                     values.example.yaml omits it, so nobody validates that \
                     input and the example cannot be copied as a starting point",
                    builtin.selector(),
                );
            }
        }

        for name in values.keys() {
            assert!(
                manifest.inputs.contains_key(name),
                "{} publishes example value {name:?} that its manifest does \
                 not declare; the example would be rejected at compile time",
                builtin.selector(),
            );
        }
    }
}

#[test]
fn unknown_inputs_are_rejected() {
    let catalog = RecipeCatalog::builtin().expect("the built-in catalog must construct");

    for builtin in BUILTINS {
        let package = catalog.resolve(&builtin.selector()).expect("resolves");
        let mut values = builtin.example_values();
        values.insert(
            "definitely_not_a_declared_input".to_owned(),
            Value::String("x".to_owned()),
        );

        assert!(
            package.compile(&values).is_err(),
            "{} accepted an undeclared input. Silently ignoring unknown keys \
             hides operator typos in production configuration.",
            builtin.selector(),
        );
    }
}

#[test]
fn missing_required_inputs_are_rejected() {
    let catalog = RecipeCatalog::builtin().expect("the built-in catalog must construct");

    for builtin in BUILTINS {
        let package = catalog.resolve(&builtin.selector()).expect("resolves");
        let manifest = package.manifest();

        for (name, definition) in &manifest.inputs {
            if !definition.required || definition.default.is_some() {
                continue;
            }
            let mut values = builtin.example_values();
            values.remove(name);

            assert!(
                package.compile(&values).is_err(),
                "{} compiled without required input {name:?}",
                builtin.selector(),
            );
        }
    }
}

#[test]
fn sip_security_rejects_values_outside_its_enum() {
    let catalog = RecipeCatalog::builtin().expect("the built-in catalog must construct");
    let mut checked = 0usize;

    for builtin in BUILTINS {
        let package = catalog.resolve(&builtin.selector()).expect("resolves");
        if !package.manifest().inputs.contains_key("sip_security") {
            continue;
        }
        checked += 1;

        // Plain RTP must never be reachable by typo. It is a deliberate
        // diagnostic posture selected by an exact enum value.
        for bogus in ["plaintext", "sips", "none", "SIPS_SRTP", ""] {
            let mut values = builtin.example_values();
            values.insert("sip_security".to_owned(), Value::String(bogus.to_owned()));
            assert!(
                package.compile(&values).is_err(),
                "{} accepted sip_security={bogus:?}, which is not in its \
                 declared enum. A near-miss must fail closed rather than \
                 silently downgrade the security posture.",
                builtin.selector(),
            );
        }
    }

    assert!(
        checked > 0,
        "no built-in declares sip_security; this test is no longer covering \
         anything and its assumptions need revisiting",
    );
}

// ---------------------------------------------------------------------------
// Layer 2 — the CLI surface bridgefu-vapi-awsconnect drives
// ---------------------------------------------------------------------------

/// Run the real binary, exactly as the AMI runtime and its qualification
/// harness do.
fn bridgefu(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bridgefu"))
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("the bridgefu binary must be runnable")
}

fn stdout_of(output: &std::process::Output, what: &str) -> String {
    assert!(
        output.status.success(),
        "{what} failed ({}):\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn cli_lists_every_builtin() {
    let listed = stdout_of(&bridgefu(&["recipe", "available"]), "recipe available");

    for builtin in BUILTINS {
        assert!(
            listed.contains(&builtin.selector()),
            "`recipe available` omitted {}:\n{listed}",
            builtin.selector(),
        );
    }
}

#[test]
fn cli_shows_and_validates_every_builtin() {
    for builtin in BUILTINS {
        let selector = builtin.selector();

        let shown = stdout_of(
            &bridgefu(&["recipe", "show", &selector]),
            &format!("recipe show {selector}"),
        );
        assert!(
            shown.contains(builtin.name),
            "`recipe show {selector}` did not name the recipe:\n{shown}",
        );

        let values = builtin.values_path();
        let values = values.to_str().expect("fixture path is UTF-8");
        let validated = stdout_of(
            &bridgefu(&["recipe", "validate", &selector, "--values", values]),
            &format!("recipe validate {selector}"),
        );

        // The CLI is what an operator uses to confirm what they are about to
        // deploy, so it must surface the same fingerprint the compiler pins.
        assert!(
            validated.contains("fingerprint:"),
            "`recipe validate {selector}` printed no fingerprint:\n{validated}",
        );
    }
}

#[test]
fn cli_rejects_a_recipe_whose_values_do_not_match() {
    // sip-webrtc-bridge's values cannot satisfy the Amazon Connect recipe.
    let output = bridgefu(&[
        "recipe",
        "validate",
        "builtin:vapi-amazon-connect-screen-pop@1",
        "--values",
        "recipes/sip-webrtc-bridge/values.example.yaml",
    ]);

    assert!(
        !output.status.success(),
        "the CLI accepted another recipe's values. Cross-recipe values must \
         fail closed rather than compile into a half-configured bridge.",
    );
}

/// The single most valuable assertion in this file.
///
/// `bridgefu-vapi-awsconnect` renders `image/runtime/bridgefu.yaml.tmpl` into
/// `/etc/bridgefu/bridgefu.yaml` and the AMI runs `bridgefu --config` against
/// it. If a schema change here would break that customer AMI, this fails in
/// Bridgefu's own CI rather than after the downstream commit pin is bumped.
#[test]
fn production_config_shape_still_validates() {
    let fixture = repo_root()
        .join("tests")
        .join("fixtures")
        .join("vapi-amazon-connect-production.yaml");
    let fixture = fixture.to_str().expect("fixture path is UTF-8");

    let output = Command::new(env!("CARGO_BIN_EXE_bridgefu"))
        .args(["--config", fixture, "validate"])
        .current_dir(repo_root())
        // The production template references both secrets indirectly. Supplying
        // them here also asserts that `env:` indirection keeps working, since
        // the AMI never writes secret material into the YAML.
        .env("BRIDGEFU_API_BEARER_TOKEN", "x".repeat(48))
        .env("BRIDGEFU_CONTROL_HMAC_KEY", "y".repeat(48))
        .output()
        .expect("the bridgefu binary must be runnable");

    assert!(
        output.status.success(),
        "the production configuration shipped by bridgefu-vapi-awsconnect no \
         longer validates:\n{}\n\nThis is the configuration baked into the \
         customer AMI. Either restore compatibility, or change \
         image/runtime/bridgefu.yaml.tmpl in that repository and this fixture \
         together before bumping its Bridgefu commit pin.",
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn production_config_keeps_secrets_out_of_the_file() {
    let fixture = repo_root()
        .join("tests")
        .join("fixtures")
        .join("vapi-amazon-connect-production.yaml");
    let rendered = std::fs::read_to_string(&fixture).expect("fixture must exist");

    for (key, field) in [
        ("bearer_token:", "api.bearer_token"),
        ("control_hmac_key:", "api.control_hmac_key"),
    ] {
        let line = rendered
            .lines()
            .find(|line| line.trim_start().starts_with(key))
            .unwrap_or_else(|| panic!("{field} is missing from the fixture"));
        assert!(
            line.contains("env:"),
            "{field} must stay an `env:` reference so the AMI never bakes a \
             secret into /etc/bridgefu/bridgefu.yaml; found: {line}",
        );
    }
}

/// A scratch directory that removes itself even if the test panics.
///
/// Std-only on purpose: pulling in `tempfile` would change `Cargo.lock`, which
/// `bridgefu-vapi-awsconnect` SHA-256s as an AMI build input. Cleanup lives in
/// `Drop` rather than at the end of the test body so a failing assertion leaves
/// no litter in the system temp directory.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "bridgefu-recipe-matrix-{}-{label}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&path);
        Self { path }
    }

    /// The directory `recipe init` should create. It must not exist yet.
    fn starter(&self) -> PathBuf {
        self.path.join("starter")
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// `recipe init` is how an operator starts a real deployment, so the starter it
/// writes has to name exactly the inputs the recipe declares, round-trip with
/// real values, and never clobber edits already made.
#[test]
fn cli_init_writes_a_faithful_starter() {
    let catalog = RecipeCatalog::builtin().expect("the built-in catalog must construct");

    for builtin in BUILTINS {
        let selector = builtin.selector();
        let root = ScratchDir::new(builtin.name);
        let out = root.starter();
        let out_str = out.to_str().expect("scratch path is UTF-8").to_owned();

        stdout_of(
            &bridgefu(&["recipe", "init", &selector, "--output", &out_str]),
            &format!("recipe init {selector}"),
        );

        for expected in ["values.yaml", "recipe-selection.yaml", "INPUTS.md"] {
            assert!(
                out.join(expected).is_file(),
                "`recipe init {selector}` did not write {expected}",
            );
        }

        // The starter must offer exactly the recipe's declared inputs: a
        // missing key strands the operator, an extra key fails to compile.
        let starter: BTreeMap<String, Value> = serde_yaml::from_str(
            &std::fs::read_to_string(out.join("values.yaml")).expect("values.yaml is readable"),
        )
        .expect("values.yaml is a YAML mapping");
        // `recipe init` seeds every required input plus every optional input
        // that carries a default, and deliberately omits optional inputs with
        // no default (outbound proxies, digest auth, bearer tokens) so the
        // starter stays the shortest thing an operator must actually fill in.
        let inputs = &catalog
            .resolve(&selector)
            .expect("resolves")
            .manifest()
            .inputs;
        let expected: Vec<&String> = inputs
            .iter()
            .filter(|(_, definition)| definition.required || definition.default.is_some())
            .map(|(name, _)| name)
            .collect();
        let offered: Vec<&String> = starter.keys().collect();
        assert_eq!(
            offered, expected,
            "`recipe init {selector}` offered a different input set than \
             expected. Every required input, and every optional input with a \
             default, must appear; optional inputs without a default must not.",
        );

        // Whatever is omitted must be genuinely optional. Dropping a required
        // input would hand the operator a starter that cannot compile.
        for (name, definition) in inputs {
            if !starter.contains_key(name) {
                assert!(
                    !definition.required,
                    "`recipe init {selector}` omitted required input {name:?}",
                );
            }
        }

        // Once real values are supplied, the starter's shape compiles.
        std::fs::copy(builtin.values_path(), out.join("values.yaml"))
            .expect("published example is copyable over the starter");
        stdout_of(
            &bridgefu(&[
                "recipe",
                "validate",
                &selector,
                "--values",
                out.join("values.yaml").to_str().expect("UTF-8"),
            ]),
            &format!("filled starter for {selector}"),
        );

        // Re-running must refuse rather than discard operator edits.
        assert!(
            !bridgefu(&["recipe", "init", &selector, "--output", &out_str])
                .status
                .success(),
            "`recipe init {selector}` overwrote an existing directory, which \
             would silently destroy an operator's filled-in values",
        );
    }
}

/// Pins an inconsistency in `recipe init` rather than papering over it.
///
/// `src/main.rs` seeds `vapi-amazon-connect-screen-pop`'s starter from that
/// recipe's `values.example.yaml`, while every other recipe gets `null`
/// placeholders. The consequence is that the Vapi starter *passes*
/// `recipe validate` untouched, because RFC 5737 addresses and the documented
/// `123456789012` account are all well-formed. An operator can therefore run
/// `init` then `validate`, see success, and believe they have configured
/// something they have not.
///
/// That is a `src/` behavior change, deliberately out of scope for the
/// repository cleanup that introduced this file. This test records today's
/// split so that changing it -- in either direction -- is a decision someone
/// makes on purpose rather than a silent drift.
#[test]
fn cli_init_fail_closed_behavior_is_recorded() {
    let catalog = RecipeCatalog::builtin().expect("the built-in catalog must construct");

    for builtin in BUILTINS {
        let selector = builtin.selector();
        let seeded_from_example = builtin.name == "vapi-amazon-connect-screen-pop";

        let inputs = &catalog
            .resolve(&selector)
            .expect("resolves")
            .manifest()
            .inputs;

        let root = ScratchDir::new(&format!("failclosed-{}", builtin.name));
        let out = root.starter();
        let out_str = out.to_str().expect("scratch path is UTF-8").to_owned();
        stdout_of(
            &bridgefu(&["recipe", "init", &selector, "--output", &out_str]),
            &format!("recipe init {selector}"),
        );

        let unedited_validates = bridgefu(&[
            "recipe",
            "validate",
            &selector,
            "--values",
            out.join("values.yaml").to_str().expect("UTF-8"),
        ])
        .status
        .success();

        assert_eq!(
            unedited_validates, seeded_from_example,
            "`recipe init {selector}` changed its placeholder behavior. \
             Recipes seeded from their published example validate untouched; \
             recipes given null placeholders must fail closed. Today only \
             vapi-amazon-connect-screen-pop is seeded (src/main.rs). If you \
             meant to change that, update this test and say so.",
        );

        // Whatever the placeholder policy, no starter may carry a secret.
        let raw = std::fs::read_to_string(out.join("values.yaml")).expect("readable");
        for leaked in ["BEGIN ", "-----BEGIN", "AKIA", "password:"] {
            assert!(
                !raw.contains(leaked),
                "the starter for {selector} contains {leaked:?}; `recipe init` \
                 must never emit credential material",
            );
        }

        // The seeding policy changes the placeholder *values*, never which
        // inputs the starter offers.
        let offered = inputs
            .iter()
            .filter(|(_, definition)| definition.required || definition.default.is_some())
            .count();
        assert_eq!(
            offered,
            serde_yaml::from_str::<BTreeMap<String, Value>>(&raw)
                .expect("YAML mapping")
                .len(),
            "the seeding policy for {selector} changed which inputs appear",
        );
    }
}

// ---------------------------------------------------------------------------
// Composition: recipe -> configuration -> concrete runtime transports
// ---------------------------------------------------------------------------

/// Every built-in recipe, the credential-free configuration that selects it,
/// and the transports that configuration must project it onto.
///
/// This is the half of the composition the compile gate above cannot reach.
/// Compiling a recipe standalone proves the manifest and its inputs agree; it
/// does not prove the recipe survives being selected from a complete
/// configuration, where the edge listener, API TLS, and admission policy all
/// have to be present and consistent. Each fixture here is first run through
/// `validate` -- the full runtime preflight -- and only then explained.
///
/// Scope, stated precisely. `recipe explain` reports the transport posture the
/// configured inputs produce; the port numbers in its output are display
/// constants in `explain_compiled_recipe`, keyed off `sip_security` alone, and
/// are NOT read back from the configuration's `edge` block. So these assertions
/// pin "the operator's values drove this posture, inside a configuration that
/// passes preflight". They do not pin listener addresses, and they place no
/// call. What carries real media is the hermetic transport coverage listed in
/// the repository README.
const PROJECTIONS: &[(&str, &str, &str, &str)] = &[
    (
        "vapi-amazon-connect-production.yaml",
        "vapi-amazon-connect-screen-pop@1",
        "source: SIP (SIPS with preferred SRTP; TCP 5061; UDP 16384-32767); \
         admission=managed one-use attachment",
        "destination: Amazon Connect WebRTC; instance and flow configured (redacted)",
    ),
    (
        "recipe-configs/webrtc-amazon.yaml",
        "webrtc-amazon-connect-bridge@1",
        "source: WebRTC; signaling=configured (redacted)",
        "destination: Amazon Connect WebRTC; instance and flow configured (redacted)",
    ),
    (
        "recipe-configs/sip-webrtc.yaml",
        "sip-webrtc-bridge@1",
        "source: SIP (SIPS/SRTP; TCP 5061; UDP 16384-32767); \
         admission=managed one-use attachment",
        "destination: WebRTC; signaling=configured (redacted)",
    ),
    (
        "recipe-configs/webrtc-sip.yaml",
        "webrtc-sip-bridge@1",
        "source: WebRTC; signaling=configured (redacted)",
        "destination: SIP (SIPS/SRTP; TCP 5061; UDP 16384-32767); \
         target_uri=configured (redacted)",
    ),
];

/// Run the binary against a fixture configuration with both secrets supplied by
/// reference, exactly as a deployment does.
fn bridgefu_with_config(fixture: &str, args: &[&str]) -> std::process::Output {
    let path = repo_root().join("tests").join("fixtures").join(fixture);
    let mut argv = vec!["--config", path.to_str().expect("fixture path is UTF-8")];
    argv.extend_from_slice(args);
    Command::new(env!("CARGO_BIN_EXE_bridgefu"))
        .args(&argv)
        .current_dir(repo_root())
        .env("BRIDGEFU_API_BEARER_TOKEN", "x".repeat(48))
        .env("BRIDGEFU_CONTROL_HMAC_KEY", "y".repeat(48))
        .output()
        .expect("the bridgefu binary must be runnable")
}

#[test]
fn every_recipe_projects_onto_its_declared_transports() {
    for (fixture, selector, source, destination) in PROJECTIONS {
        stdout_of(
            &bridgefu_with_config(fixture, &["validate"]),
            &format!("validate {fixture}"),
        );

        let explained = stdout_of(
            &bridgefu_with_config(fixture, &["recipe", "explain", "support"]),
            &format!("recipe explain for {fixture}"),
        );

        assert!(
            explained.contains(selector),
            "{fixture} did not project {selector}:\n{explained}",
        );
        for expected in [source, destination] {
            assert!(
                explained.contains(expected),
                "{fixture} projected the wrong transport.\n  expected: {expected}\n\
                 got:\n{explained}",
            );
        }
        assert!(
            explained.contains("projection conflicts: none"),
            "{fixture} reported projection conflicts:\n{explained}",
        );
    }
}

#[test]
fn projection_never_reveals_a_secret() {
    for (fixture, _, _, _) in PROJECTIONS {
        let explained = stdout_of(
            &bridgefu_with_config(fixture, &["recipe", "explain", "support"]),
            &format!("recipe explain for {fixture}"),
        );
        assert!(
            explained.contains("secrets: redacted"),
            "{fixture} dropped the redaction notice:\n{explained}",
        );
        // The configured ARN, flow id, and URIs are operator data. `explain` is
        // what someone pastes into a ticket, so it must stay paste-safe.
        for leaked in ["123456789012", "22222222-2222", "wss://", "sips:"] {
            assert!(
                !explained.contains(leaked),
                "{fixture} leaked {leaked:?} into `recipe explain`:\n{explained}",
            );
        }
    }
}

#[test]
fn projection_fingerprint_reflects_configured_values() {
    // The Vapi recipe's own example uses sips_srtp and one CIDR; the production
    // fixture uses sips_optional_srtp and two. Same recipe, different inputs, so
    // the fingerprints must differ -- otherwise the fingerprint is not actually
    // binding the values an operator supplied.
    let catalog = RecipeCatalog::builtin().expect("the built-in catalog must construct");
    let standalone = catalog
        .resolve("builtin:vapi-amazon-connect-screen-pop@1")
        .expect("resolves")
        .compile(&BUILTINS[0].example_values())
        .expect("compiles")
        .fingerprint;

    let explained = stdout_of(
        &bridgefu_with_config(
            "vapi-amazon-connect-production.yaml",
            &["recipe", "explain", "support"],
        ),
        "recipe explain for the production fixture",
    );

    assert!(
        !explained.contains(&standalone),
        "the configured projection reported the same fingerprint as the \
         standalone example compile ({standalone}), even though the \
         configuration supplies different sip_security and CIDRs. The \
         fingerprint would not be binding operator input.",
    );
}
