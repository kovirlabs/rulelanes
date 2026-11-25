//! R2: unsupported syntax is refused at load with the file, the decoder or
//! rule, and the element named.

use rulelanes_syntax::error::ErrorKind;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

fn base_decoders() -> Vec<PathBuf> {
    rulelanes_syntax::xml_files(&root().join("ruleset/decoders")).unwrap()
}

fn base_rules() -> Vec<PathBuf> {
    rulelanes_syntax::xml_files(&root().join("ruleset/rules")).unwrap()
}

/// (fixture, item named in the error, element named in the error)
const CASES: &[(&str, &str, &str)] = &[
    ("d-fts.xml", "decoder 'rlu-fts'", "<fts>"),
    ("d-accumulate.xml", "decoder 'rlu-acc'", "<accumulate>"),
    (
        "d-plugin.xml",
        "decoder 'rlu-pf'",
        "<plugin_decoder>PF_Decoder",
    ),
    ("d-adjacent-groups.xml", "decoder 'rlu-adjacent'", "<regex>"),
    ("r-frequency.xml", "rule 881001", "rule@frequency"),
    ("r-if_matched_sid.xml", "rule 881002", "<if_matched_sid>"),
    ("r-list.xml", "rule 881003", "<list>"),
    ("r-same_source_ip.xml", "rule 881004", "<same_source_ip>"),
    ("r-options.xml", "rule 881005", "<options>no_log"),
];

#[test]
fn unsupported_syntax_is_refused_and_named() {
    for (file, item, element) in CASES {
        let f = root().join("unsupported").join(file);
        let (decs, rules) = if file.starts_with("d-") {
            let mut d = base_decoders();
            d.push(f.clone());
            (d, base_rules())
        } else {
            let mut r = base_rules();
            r.push(f.clone());
            (base_decoders(), r)
        };
        let err = rulelanes_syntax::load_files(&decs, &rules)
            .err()
            .unwrap_or_else(|| panic!("{file}: loaded, but must be refused"));
        assert_eq!(err.kind, ErrorKind::Unsupported, "{file}: {err}");
        let msg = err.to_string();
        assert!(
            msg.contains(file),
            "{file}: message does not name the file: {msg}"
        );
        assert!(
            msg.contains(item),
            "{file}: message does not name {item}: {msg}"
        );
        assert!(
            msg.contains(element),
            "{file}: message does not name {element}: {msg}"
        );
    }
}

#[test]
fn the_test_ruleset_loads_strictly() {
    let set = rulelanes_syntax::load_files(&base_decoders(), &base_rules()).unwrap();
    assert!(set.decoders.len() >= 20);
    assert!(set.rules.len() >= 50);
}
