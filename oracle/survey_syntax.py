#!/usr/bin/env python3
"""Count decoder and rule elements and attributes in a Wazuh ruleset.

Run inside the Wazuh manager container (see oracle/README.md). It reads the
ruleset from disk at run time and prints counts as JSON; no ruleset content
is printed or stored. Written for rulelanes; Apache-2.0 (TBD).

The Wazuh XML dialect is not always well-formed XML (several roots per file,
`\<` escapes in patterns), so this uses a small tolerant tag scanner rather
than an XML library.
"""
import json
import os
import re
import sys
from collections import Counter, defaultdict

TAG = re.compile(r'<(/?)([A-Za-z_][\w.:-]*)((?:[^>"]|"[^"]*")*?)(/?)>')
ATTR = re.compile(r'([A-Za-z_][\w.:-]*)\s*=\s*"([^"]*)"')
COMMENT = re.compile(r'<!--.*?-->', re.S)


def scan(text):
    """Yield (kind, name, attrs, text_after) for each tag. kind: open/close/empty."""
    text = COMMENT.sub(lambda m: ' ' * len(m.group(0)), text)
    pos = 0
    while True:
        m = TAG.search(text, pos)
        if not m:
            return
        # A `<` escaped as `\<` is pattern text, not a tag.
        if m.start() > 0 and text[m.start() - 1] == chr(92):
            pos = m.start() + 1
            continue
        closing, name, attrs, empty = m.groups()
        kind = 'close' if closing else ('empty' if empty else 'open')
        yield kind, name, dict(ATTR.findall(attrs)), m.end()
        pos = m.end()


def survey(paths, item_tag):
    elems = Counter()          # child element name -> occurrences
    attrs = Counter()          # "elem@attr" -> occurrences
    values = defaultdict(Counter)  # "elem@attr" -> value -> occurrences (for small enums)
    item_attrs = Counter()     # attributes on the item tag itself
    items = 0
    files = 0
    other_top = Counter()
    for path in paths:
        files += 1
        with open(path, encoding='utf-8', errors='replace') as f:
            text = f.read()
        stack = []
        for kind, name, a, _ in scan(text):
            if kind == 'close':
                if stack and stack[-1] == name:
                    stack.pop()
                continue
            depth_item = item_tag in stack
            if name == item_tag:
                items += 1
                for k, v in a.items():
                    item_attrs[k] += 1
                    if k in ('overwrite', 'noalert', 'accuracy'):
                        values[item_tag + '@' + k][v] += 1
            elif depth_item and stack[-1] == item_tag:
                elems[name] += 1
                for k, v in a.items():
                    key = name + '@' + k
                    attrs[key] += 1
                    if k in ('type', 'offset', 'negate', 'name' if name == 'field' else '-', 'lookup', 'check'):
                        if k != 'name':
                            values[key][v] += 1
                if name == 'plugin_decoder':
                    stack_text = None
            elif not depth_item and not stack:
                other_top[name] += 1
            if kind == 'open':
                stack.append(name)
    return {
        'files': files,
        'items': items,
        'item_attributes': dict(item_attrs.most_common()),
        'elements': dict(elems.most_common()),
        'element_attributes': dict(attrs.most_common()),
        'attribute_values': {k: dict(v.most_common()) for k, v in sorted(values.items())},
        'top_level_tags': dict(other_top.most_common()),
    }


def plugin_and_options(paths, tag):
    """Count text values of one element (e.g. plugin_decoder, options)."""
    c = Counter()
    pat = re.compile(r'<' + tag + r'(?:\s[^>]*)?>([^<]*)</' + tag + r'>')
    for path in paths:
        with open(path, encoding='utf-8', errors='replace') as f:
            text = COMMENT.sub('', f.read())
        for v in pat.findall(text):
            c[v.strip()] += 1
    return dict(c.most_common())


def xml_files(d):
    return sorted(os.path.join(d, f) for f in os.listdir(d) if f.endswith('.xml'))


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else '/var/ossec/ruleset'
    dec = xml_files(os.path.join(root, 'decoders'))
    rul = xml_files(os.path.join(root, 'rules'))
    out = {
        'ruleset_root': root,
        'decoders': survey(dec, 'decoder'),
        'rules': survey(rul, 'rule'),
        'decoder_plugin_values': plugin_and_options(dec, 'plugin_decoder'),
        'rule_options_values': plugin_and_options(rul, 'options'),
        'rule_category_values': plugin_and_options(rul, 'category'),
    }
    json.dump(out, sys.stdout, indent=1, sort_keys=False)
    print()


if __name__ == '__main__':
    main()
