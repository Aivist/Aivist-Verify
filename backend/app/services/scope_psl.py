# ==============================================================================
# Vendored Public Suffix List snapshot — MULTI-LABEL ICANN suffixes only.
#
# WHY vendored: zero runtime dependency, deterministic, works offline on a fresh
# clone. Used SOLELY by scope.py's over-broad-wildcard guard to reject a wildcard
# whose base is an entire registrable-domain space (e.g. `*.co.uk`).
#
# WHY only MULTI-LABEL suffixes: a wildcard whose base is a SINGLE label (`*`,
# `*.com`, `*.io`) is rejected structurally by label-count in scope.py and needs no
# data here. Only 2+-label public suffixes (`co.uk`, `com.au`) can pass the
# label-count check, so only those must be enumerated. This keeps the snapshot small
# and reviewable instead of vendoring the full ~15k-line list.
#
# PROVENANCE: curated from the ICANN section of the Mozilla Public Suffix List
#   https://publicsuffix.org/list/public_suffix_list.dat
# Point-in-time snapshot: 2026-07. This is a CURATED SUBSET of the common ccSLDs,
# not the complete list — an obscure multi-label suffix absent here would let a
# `*.obscure.suffix` wildcard through. That is a convenience/footgun guard, not the
# load-bearing control: actual traffic is still constrained by host matching + the
# resolved-IP rebinding guard in scope.py.
#
# REFRESH CADENCE: re-vendor from the URL above when adding real-target support for
# a new ccTLD region, or annually — whichever comes first. Keep it sorted by region.
# ==============================================================================
from __future__ import annotations

MULTI_LABEL_PUBLIC_SUFFIXES = frozenset({
    # United Kingdom
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "ac.uk", "gov.uk", "mod.uk", "nhs.uk", "police.uk", "nic.uk",
    # Japan
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp", "ad.jp", "ed.jp", "gr.jp", "lg.jp",
    # Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    # New Zealand
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "geek.nz", "school.nz",
    # Brazil
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    # China
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    # Hong Kong
    "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk", "idv.hk",
    # India
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "gov.in", "ac.in", "edu.in", "res.in",
    # South Africa
    "co.za", "net.za", "org.za", "gov.za", "ac.za", "web.za",
    # Mexico
    "com.mx", "net.mx", "org.mx", "gob.mx", "edu.mx",
    # Turkey
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "bel.tr", "k12.tr",
    # South Korea
    "co.kr", "ne.kr", "or.kr", "go.kr", "re.kr", "pe.kr", "ac.kr",
    # Singapore
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg", "per.sg",
    # Taiwan
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw", "idv.tw",
    # Russia
    "com.ru", "net.ru", "org.ru", "msk.ru", "spb.ru",
    # Israel
    "co.il", "org.il", "gov.il", "ac.il", "net.il", "k12.il",
    # Argentina
    "com.ar", "gob.ar", "org.ar", "edu.ar", "net.ar",
    # Indonesia
    "co.id", "or.id", "ac.id", "go.id", "net.id", "web.id",
    # Ukraine
    "com.ua", "gov.ua", "net.ua", "org.ua",
    # Poland
    "com.pl", "gov.pl", "edu.pl", "net.pl", "org.pl",
    # Thailand
    "co.th", "in.th", "ac.th", "go.th", "net.th", "or.th",
    # Malaysia
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    # Philippines
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    # Vietnam
    "com.vn", "net.vn", "gov.vn", "edu.vn", "org.vn",
    # Egypt / Saudi Arabia / Kenya
    "com.eg", "gov.eg", "com.sa", "edu.sa", "gov.sa", "co.ke",
    # Common private-section second levels worth treating as suffixes for the guard
    "eu.com", "us.com", "uk.com", "gb.com", "co.com",
})
