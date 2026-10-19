#!/usr/bin/env python3
"""Apply Dell Optimizer 6.3.5.0's install/runtime platform gate to a machine description.

Rules reconstructed from the shipped suite (see docs/08-model-and-capability-gating.md):
  * vendor must be Dell Inc. / Dell Technologies Inc.
  * product name is scanned token-by-token with the CY26 or CY25 model-ID regex
  * CustomerType (Commercial/Consumer) comes from the model-ID line (or family name for legacy names)
  * SKU decision: exact allow -> pass, exact block -> fail, else hex SKU >= AnySKU

Usage:
  gating_verdict.py --product "Inspiron 15 3535" --sku 0B9C
  gating_verdict.py --manifesturer "Dell Inc." --product "Latitude 7440" --sku 0C1F --json
"""
import argparse
import json
import re
import sys

RE_CY26 = re.compile(
    r"^(?P<productLine>D|DA|DX|C|P|PW|PR|PV|PE)(?P<tier>[SAX9753M])?"
    r"(?P<formFactor>[MRST0-9][0-9])(?P<generation>[0-9]{2})(?P<cpuVendor>[0-9])$")
RE_CY25 = re.compile(r"^[CDEPQMFR][ABCEV012789][MRST0-9][0-9]{4}$")

GATE = {
    "Commercial": {
        "families": ["Precision", "Latitude", "OptiPlex"],
        "allow": ["0971", "097E", "0738", "0739", "073A", "08B1", "0873"],
        "block": ["09F1", "09F2", "0A30", "0A31", "0A84", "0A85"],
        "anysku": "0983",
    },
    "Consumer": {
        "families": ["Inspiron", "Vostro", "XPS"],
        "allow": [],
        "block": ["0C52", "0B24", "0B31", "0AF4", "0B70", "0B25", "0B32", "0B26", "0B33", "0BB6"],
        "anysku": "0AF3",
    },
}
FAMILY_TO_TYPE = {"Inspiron": "Consumer", "Vostro": "Consumer", "XPS": "Consumer",
                  "Precision": "Commercial", "Latitude": "Commercial", "OptiPlex": "Commercial"}


def to_int(sku):
    try:
        return int(sku, 16)
    except (TypeError, ValueError):
        return None


def classify(product):
    """Return (model_id, rule, customer_type, excluded_reason)."""
    for token in product.upper().split():
        if RE_CY26.match(token):
            m = RE_CY26.match(token)
            pl = m.group("productLine")
            if pl == "C" or (pl == "DA" and len(token) == 8):
                return token, "CY26", None, "unsupported product line (Chromebook/Alienware)"
            return token, "CY26", ("Consumer" if pl == "D" else "Commercial"), None
    for token in product.upper().split():
        if RE_CY25.match(token):
            if token[0] == "C" or token[1] in "79":
                return token, "CY25", None, "unsupported product line (Chromebook/ChengMing/ThinClient)"
            return token, "CY25", ("Consumer" if token[0] in "CDE" else "Commercial"), None
    # legacy product names: match the family name
    up = product.upper()
    for fam, ctype in FAMILY_TO_TYPE.items():
        if fam.upper() in up:
            return None, "legacy", ctype, None
    return None, "legacy", None, "no known product family in product name"


def verdict(manufacturer, product, sku):
    out = {"manufacturer": manufacturer, "product": product, "sku": sku}
    if "DELL INC." not in manufacturer.upper() and "DELL TECHNOLOGIES INC." not in manufacturer.upper():
        out.update(passed=False, reason="not a Dell system (manufacturer check)")
        return out
    model_id, rule, ctype, excl = classify(product)
    out.update(model_id=model_id, naming_rule=rule, customer_type=ctype)
    if excl:
        out.update(passed=False, reason=excl)
        return out
    sections = [GATE[ctype]] if ctype else [GATE["Commercial"], GATE["Consumer"]]
    sku_i = to_int(sku)
    reasons = []
    for sec in sections:
        # family must be allowed (legacy path) or the model-ID line selects the section
        if ctype is None:
            fam_ok = any(f.upper() in product.upper() for f in sec["families"])
        else:
            fam_ok = True
        if not fam_ok:
            reasons.append("family not in allow list")
            continue
        if sku is None or sku_i is None:
            reasons.append("no/invalid SKU")
            continue
        if sku.upper() in [s.upper() for s in sec["allow"]]:
            out.update(passed=True, reason=f"SKU {sku} explicitly allowed")
            return out
        if sku.upper() in [s.upper() for s in sec["block"]]:
            reasons.append(f"SKU {sku} explicitly blocked")
            continue
        if sku_i >= int(sec["anysku"], 16):
            out.update(passed=True,
                       reason=f"SKU 0x{sku_i:04X} >= AnySKU 0x{sec['anysku']}")
            return out
        reasons.append(f"SKU 0x{sku_i:04X} < AnySKU 0x{sec['anysku']}")
    out.update(passed=False, reason="; ".join(reasons) or "no matching section")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manufacturer", default="Dell Inc.")
    ap.add_argument("--product", required=True)
    ap.add_argument("--sku", default=None)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = verdict(a.manufacturer, a.product, a.sku)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        for k, v in r.items():
            print(f"{k:16}: {v}")
    sys.exit(0 if r["passed"] else 1)


if __name__ == "__main__":
    main()
