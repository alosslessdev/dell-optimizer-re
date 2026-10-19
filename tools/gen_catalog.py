#!/usr/bin/env python3
"""Generate a per-assembly, per-type, per-function catalog from ILSpy decompilations.

Input : decompiled/ and decompiled_all/ trees (ilspycmd -p output: one .cs per type)
Output: docs/catalog/<Assembly>.md  (one line per type member)
        docs/03-function-catalog.md (index)

Parses only *declaration* lines at type-body depth 1 (no body statements), with
multi-line signature joining and attribute capture.
"""
import os, re, sys, collections

ROOT = os.environ.get('PROJECT_ROOT') or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'docs', 'catalog')

DECL_KINDS = ('class', 'struct', 'interface', 'enum', 'delegate', 'record')
CTRL = {'if', 'else', 'for', 'foreach', 'while', 'switch', 'return', 'using', 'lock', 'catch',
        'try', 'do', 'break', 'continue', 'throw', 'new', 'case', 'default', 'goto', 'fixed',
        'checked', 'unchecked', 'yield', 'in', 'out', 'ref', 'get', 'set', 'init', 'add', 'remove',
        'where', 'when', 'is', 'as', 'not', 'and', 'or'}

ATTR_RE = re.compile(r'^\s*\[(?P<attr>[^\]]*)\]\s*$')
TYPEDECL_RE = re.compile(r'^(?P<mods>(?:[\w.]+\s+)*?)(?P<kind>class|struct|interface|enum|delegate|record)\s+(?P<name>[\w.]+)')
ENUMVAL_RE = re.compile(r'^\s*(?P<name>\w+)\s*(?P<val>=[^,/]*)?')


def split_top_level(text):
    """Yield (kind, name, body_lines) for each type declaration, recursively."""
    lines = text.split('\n')
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        m = re.match(r'^namespace ([\w.]+)', line)
        if m:
            i += 1
            continue
        mt = TYPEDECL_RE.match(line)
        if mt and not line.strip().startswith('//'):
            kind, name = mt.group('kind'), mt.group('name')
            # find body block
            brace = 0
            j = i
            started = False
            while j < n:
                brace += lines[j].count('{') - lines[j].count('}')
                if '{' in lines[j]:
                    started = True
                if started and brace <= 0:
                    break
                j += 1
            body = lines[i + 1:j]
            yield kind, name, body
            i = j + 1
            continue
        i += 1


def member_lines(body):
    """Yield declaration strings at depth 1 inside a type body (attributes attached)."""
    if body and body[0].strip() == '{':
        body = body[1:]
    depth = 1
    pending_attrs = []
    i = 0
    while i < len(body):
        line = body[i]
        stripped = line.strip()
        ma = ATTR_RE.match(line)
        if depth == 1 and ma and not stripped.startswith('//'):
            pending_attrs.append(ma.group('attr'))
            i += 1
            continue
        # join multi-line signatures at depth 1
        if depth == 1 and stripped and not stripped.startswith('//') and not stripped.startswith('/*'):
            sig = line
            j = i
            while sig.count('(') > sig.count(')') and j + 1 < len(body):
                j += 1
                sig += ' ' + body[j].strip()
            yield sig, pending_attrs
            pending_attrs = []
            i = j
        elif depth > 1:
            pending_attrs = []
        depth += line.count('{') - line.count('}')
        if depth < 1:
            depth = 1
        i += 1


def classify(sig, attrs):
    """Return (kind, clean_signature, note)."""
    s = re.sub(r'\s+', ' ', sig).strip()
    if s.startswith('}'):
        return None
    note_parts = []
    for a in attrs:
        a0 = a.split('(')[0].strip()
        note_parts.append(a0)
        if a0 == 'DllImport':
            m = re.search(r'"([^"]+)"', a)
            if m:
                note_parts[-1] = f'P/Invoke {m.group(1)}'
    m = TYPEDECL_RE.match(s)
    if m:
        return ('type', f'{m.group("kind")} {m.group("name")}', '')
    if '=' in s and '(' not in s.split('=')[0] and s.endswith(','):
        me = ENUMVAL_RE.match(s)
        if me:
            return ('enumval', me.group('name'), (me.group('val') or '').strip(' =,'))
    if re.match(r'^(public|private|protected|internal|static|virtual|override|sealed|async|extern|unsafe|new|partial|readonly|const|event|explicit|implicit|operator|\s)+', s) or s.startswith('['):
        # method?
        mth = re.match(r'^(?P<pre>[\w<>\[\],.? ]+?)\((?P<args>.*)\)\s*(?P<tail>[;{].*)?$', s)
        if mth and mth.group('pre').split()[-1].split('.')[-1][:1].isupper():
            sig_clean = s.rstrip('{; ').rstrip()
            body_hint = []
            if 'NotImplementedException' in s:
                body_hint.append('throws NotImplementedException')
            if 'DllImport' in ' '.join(attrs):
                pass
            return ('method', sig_clean, '; '.join(note_parts + body_hint))
        # property
        mpr = re.match(r'^(?P<mods>(?:[\w]+\s)+)?(?P<type>[\w<>\[\],.? ]+?)\s+(?P<name>\w+)\s*\{', s)
        if mpr and not s.startswith('return'):
            return ('prop', s.split('{')[0].strip(), '; '.join(note_parts))
        # field
        mf = re.match(r'^(?P<mods>(?:[\w]+\s)+)?(?P<type>[\w<>\[\],.? ]+?)\s+(?P<name>\w+)\s*(=.*)?[;,]$', s)
        if mf and mf.group('name') not in CTRL:
            return ('field', s.rstrip(',;'), '')
    return None


def parse_file(path, ns='', prefix=''):
    out = []
    text = open(path, encoding='utf-8', errors='replace').read()
    if not prefix:
        m = re.search(r'^namespace ([\w.]+)', text, re.M)
        if m:
            ns = m.group(1)
    for kind, name, body in split_top_level(text):
        if name.startswith('<') or '__DisplayClass' in name:
            continue
        full = f'{prefix}{ns}.{name}' if ns else f'{prefix}{name}'
        out.append(('type', kind, full, ''))
        if kind == 'enum':
            for line in body:
                me = ENUMVAL_RE.match(line)
                if me and me.group('name') not in ('{', '}', ''):
                    out.append(('enumval', '', full, me.group('name') + ' ' + (me.group('val') or '').strip(' =,')))
            continue
        # top-level members (skip nested type declarations — handled below)
        for sig, attrs in member_lines(body):
            if TYPEDECL_RE.match(re.sub(r'\s+', ' ', sig).strip()):
                continue
            c = classify(sig, attrs)
            if c:
                out.append((c[0], c[2], full, c[1]))
        # nested types (one level; deeper nesting is rare in this codebase)
        for k2, n2, b2 in split_top_level('\n'.join(body)):
            if n2.startswith('<') or '__DisplayClass' in n2:
                continue
            out.append(('type', k2, f'{full}.{n2}', '(nested)'))
            if k2 == 'enum':
                for line in b2:
                    me = ENUMVAL_RE.match(line)
                    if me and me.group('name') not in ('{', '}', ''):
                        out.append(('enumval', '', f'{full}.{n2}', me.group('name') + ' ' + (me.group('val') or '').strip(' =,')))
                continue
            for sig, attrs in member_lines(b2):
                c = classify(sig, attrs)
                if c:
                    out.append((c[0], c[2], f'{full}.{n2}', c[1]))
    return out


def main():
    os.makedirs(OUT, exist_ok=True)
    by_asm = collections.defaultdict(list)
    for tree in (os.path.join(ROOT, 'decompiled'), os.path.join(ROOT, 'decompiled_all')):
        if not os.path.isdir(tree):
            continue
        for dirpath, dirs, files in os.walk(tree):
            rel = os.path.relpath(dirpath, tree)
            if rel == '.':
                continue
            asm = rel.split(os.sep)[0]
            if re.search(r'(<|>__|PrivateImplementation)', asm):
                continue
            for f in sorted(files):
                if f.endswith('.cs') and f != 'AssemblyInfo.cs':
                    by_asm[asm].extend(parse_file(os.path.join(dirpath, f)))
    index = []
    for asm in sorted(by_asm):
        entries = [e for e in by_asm[asm] if not e[3] == '(nested)' or e[0] == 'type']
        types = sum(1 for e in entries if e[0] == 'type')
        funcs = sum(1 for e in entries if e[0] in ('method', 'prop', 'field', 'enumval'))
        with open(os.path.join(OUT, asm + '.md'), 'w') as out:
            out.write(f'# {asm} — complete function catalog\n\n')
            out.write(f'{types} types, {funcs} members (auto-generated from ILSpy decompilation)\n')
            for kind, note, t, sig in entries:
                if kind == 'type':
                    out.write(f'\n## {sig} {t} {note}\n\n')
                elif kind == 'enumval':
                    out.write(f'* `{sig}`\n')
                elif kind == 'field':
                    out.write(f'* `{sig}`\n')
                else:
                    out.write(f'* `{sig}`' + (f'  ‹{note}›' if note else '') + '\n')
        index.append((asm, types, funcs))
    with open(os.path.join(ROOT, 'docs', '03-function-catalog.md'), 'w') as out:
        out.write('# 03 — Function catalog index (all assemblies)\n\n')
        out.write('Auto-generated from decompiled C#: one entry per type member in `docs/catalog/<Assembly>.md`.\n')
        out.write('Prose analysis: `docs/02-battery-charge-levels.md`, `docs/04-battery-adjacent-features.md`,\n')
        out.write('`docs/06-functions-*.md`, `docs/05-native-bios-interface.md`.\n\n')
        out.write('| Assembly | Types | Members |\n|---|---|---|\n')
        for asm, t, f in index:
            out.write(f'| [{asm}](catalog/{asm}.md) | {t} | {f} |\n')
        out.write(f'\nTotal: {len(index)} assemblies, {sum(t for _, t, _ in index)} types, '
                  f'{sum(f for _, _, f in index)} members\n')
    print('assemblies', len(index), 'types', sum(t for _, t, _ in index), 'members', sum(f for _, _, f in index))


if __name__ == '__main__':
    main()
