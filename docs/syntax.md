# Supported syntax

M0 survey of the stock Wazuh 4.14.10 ruleset, read inside the manager
container (`/var/ossec/ruleset`) by `oracle/survey_syntax.py` on 2026-11-22.
Raw counts: `docs/syntax-survey-wazuh-4.14.10.json`. Only counts are
recorded; no decoder or rule text is copied.

Scope: 120 decoder files with 1,575 `<decoder>` elements; 168 rule files with
4,515 `<rule>` elements in 211 `<group>` blocks (plus 28 top-level `<var>`).
Counts are occurrences of the element as a direct child of `<decoder>` or
`<rule>`.

Legend for the M1 column: **M1** supported in M1; **M3** planned (SPEC §4);
**no** rejected at load with a message (R2); **meta** accepted and kept for
output, has no effect on matching.

## Decoders

| Element | Count | Attributes seen (count) | M1 |
| --- | ---: | --- | --- |
| `regex` | 1,436 | `offset` 528 (`after_parent` 238, `after_regex` 155, `after_prematch` 135); `type="pcre2"` 158 | M1 (osregex, pcre2; all three offsets) |
| `order` | 1,388 | | M1 |
| `parent` | 1,367 | | M1 |
| `prematch` | 580 | `offset="after_parent"` 178; `type="pcre2"` 21 | M1 (osregex, pcre2) |
| `program_name` | 110 | none | M1 (osmatch default; osregex, pcre2 by `type`) |
| `type` | 107 | | M1 (sets the rule category) |
| `fts` | 22 | | no |
| `plugin_decoder` | 11 | `offset` 4 (`after_prematch` 2, `after_parent` 2); values: `JSON_Decoder` 6, `OSSECAlert_Decoder` 2, `PF_Decoder` 1, `SonicWall_Decoder` 1, `SymantecWS_Decoder` 1 | M1 for `JSON_Decoder` only; other plugins no |
| `use_own_name` | 9 | | M1 |
| `accumulate` | 5 | | no |
| `ftscomment` | 4 | | no |
| `json_null_field` | 1 | | no |
| `json_array_structure` | 0 | | no |
| `var` (file level) | 0 | | M1 (cheap; used by rule files) |
| `decoder@name` | 1,575 | | M1 |

## Rules

| Element or attribute | Count | Attributes seen (count) | M1 |
| --- | ---: | --- | --- |
| `rule@id`, `rule@level` | 4,515 | | M1 |
| `rule@frequency` | 208 | | M3 |
| `rule@timeframe` | 200 | | M3 |
| `rule@ignore` | 49 | | M3 |
| `rule@noalert` | 40 | value `1` | M1 |
| `rule@maxsize` | 2 | | no |
| `rule@overwrite` | 0 | | M1 (SPEC lists it) |
| `description` | 4,564 | | M1 |
| `if_sid` | 3,868 | | M1 |
| `field` | 3,182 | `name` 3,182; `type` 517 (`pcre2` 342, `osregex` 175); `negate="yes"` 29 | M1 (osregex default, osmatch, pcre2, negate) |
| `group` | 2,443 | | M1 |
| `options` | 2,273 | values `no_full_log` 2,268, `no_log` 5, `no_email_alert` 1 | meta (`no_full_log`, `no_email_alert`); `no_log`: see M1 status |
| `mitre` | 1,064 | | meta |
| `match` | 782 | `type="pcre2"` 9 | M1 (osmatch default, osregex, pcre2, negate) |
| `id` | 286 | | M1 |
| `decoded_as` | 233 | | M1 |
| `if_matched_sid` | 205 | | M3 |
| `regex` | 148 | `type="pcre2"` 5; `negate` 1 | M1 |
| `if_group` | 130 | | M1 |
| `same_source_ip` | 123 | | M3 |
| `info` | 108 | `type` 99 (`link` 87, `text` 7, `cve` 5) | meta |
| `action` | 77 | `type="pcre2"` 11; `negate` 2 | M1 |
| `status` | 75 | | M1 |
| `url` | 47 | | M1 |
| `category` | 35 | values `ossec` 19, `windows` 5, `firewall` 3, `ids` 3, `web-log` 2, `squid` 2, `syslog` 1 | M1 |
| `program_name` | 33 | | M1 |
| `list` | 25 | `field`, `lookup` 25 (`match_key` 20, `match_key_value` 5), `check_value` 5 | no (CDB lists TBD) |
| `extra_data` | 9 | | M1 |
| `if_fts` | 8 | | no |
| `same_field` | 7 | | M3 |
| `if_matched_group` | 6 | | M3 |
| `same_id` | 5 | | M3 |
| `user` | 5 | | M1 |
| `different_url` | 5 | | M3 |
| `check_diff` | 3 | | no |
| `same_user` | 3 | | M3 |
| `check_if_ignored` | 3 | | no |
| `compiled_rule` | 3 | | no |
| `location` | 2 | | M1 |
| `ignore` | 2 | | M3 |
| `hostname` | 1 | | M1 |
| `time` | 1 | | no |
| `weekday` | 1 | | no |
| `same_location` | 1 | | M3 |
| `srcip`, `dstip`, `srcport`, `dstport` | 0 | | M1 (SPEC lists them) |

Anything not in these tables (for example `if_level`, `srcgeoip`,
`system_name`, `protocol`, `data`) is rejected at load in M1.

## M1 subset

Chosen from the counts, most used first, plus the elements the spec named.

**Decoders:** `decoder@name`, `parent`, `regex` (types osregex and pcre2;
offsets `after_parent`, `after_prematch`, `after_regex`), `order` (static
and dynamic field names), `prematch` (osregex and pcre2; offset
`after_parent`), `program_name` (osmatch, osregex, pcre2), `type`,
`use_own_name`, `plugin_decoder` with `JSON_Decoder` (offset
`after_parent`/`after_prematch`), file-level `var`. Sibling decoders that
share a name (multi-regex children) are supported.

**Rules:** `rule@id`, `rule@level`, `rule@noalert`, `rule@overwrite`,
`group` (enclosing `group@name` and per-rule), `description`, `if_sid`,
`if_group`, `decoded_as`, `category`, `match`, `regex`, `field`
(`name`, `type`, `negate`), `id`, `action`, `status`, `url`,
`extra_data`, `program_name`, `hostname`, `user`, `location`, `srcip`,
`dstip`, `srcport`, `dstport` (all with `type` and `negate` where Wazuh
allows them), and the output-only `options`, `mitre`, `info`.

**Pattern languages:** osmatch and osregex are re-implemented from their
documented and observed semantics; pcre2 patterns are compiled with a
backtracking engine that supports look-around and backreferences
(`fancy-regex`, MIT), and features it lacks are rejected at load.

## Evan's UniFi decoder and rules

`evangress/wazuh-unifi-decoder` (153 decoders) and
`evangress/wazuh-unifi-rules` (33 rules, IDs 100010–100392 inside the
reserved range 100010–100399) use only elements in the M1 subset:
`decoder@name`, `parent`, `order`, `regex type="pcre2"` (151),
`prematch type="pcre2"` (2), `program_name type="pcre2"` (1), and in the
rules `rule@id/level`, `group`, `if_sid`, `field` (37, default osregex and
pcre2), `description`, `decoded_as`. M1 runs `rulelanes check` on them
(report only).

## Corrections to SPEC §4 found in M0

- Decoder `prematch` and `regex` accept only `osregex` (default) and
  `pcre2`. `osmatch` is accepted only by decoder `program_name` (where it is
  the default). The spec listed "the three pattern types" for decoders.
- `field` (3,182 uses) is the second most used rule element after
  `if_sid`; the spec had it and so does M1. Its `type` defaults to
  `osregex`; 342 stock uses set `pcre2`.
- PCRE2 patterns in practice use look-ahead (for example 150 of the 151
  decoder regexes in Evan's UniFi decoder), so the pcre2 engine must support
  it. The spec did not say.
- `srcip`, `dstip`, `srcport`, `dstport` appear in no stock rule, `user`
  in 5 and `hostname` in 1. They stay in M1 because the spec named them and
  they are cheap, but they contribute almost nothing to stock coverage.
- `action`, `status`, `url`, `category` (77, 75, 47, 35 uses) were missing
  from the spec's subset and are added.
