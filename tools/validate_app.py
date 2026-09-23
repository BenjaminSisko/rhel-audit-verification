#!/usr/bin/env python3
"""Validate the internal AU-2 Linux Splunk app without running Splunk."""

from __future__ import annotations

import argparse
import configparser
import csv
import io
import pathlib
import re
import sys
import tarfile
import xml.etree.ElementTree as ET


REQUIRED_OUTCOMES = {
    "AU-2.a.1": {("Sign-in", "success"), ("Sign-in", "failure"), ("Sign-out", "success")},
    "AU-2.a.2": {
        (action, outcome)
        for action in ("Create", "Read/access", "Delete", "Modify", "Change permission", "Change ownership")
        for outcome in ("success", "failure")
    },
    "AU-2.a.3": {
        ("Export/write/download to media", outcome) for outcome in ("success", "failure")
    },
    "AU-2.a.4": {
        ("Import/upload from media", outcome) for outcome in ("success", "failure")
    },
    "AU-2.a.5": {
        (action, outcome)
        for action in (
            "Add user",
            "Delete user",
            "Modify user",
            "Disable user",
            "Lock user",
            "Add group/role",
            "Delete group/role",
            "Modify group/role",
        )
        for outcome in ("success", "failure")
    },
    "AU-2.a.6": {
        (action, outcome)
        for action in ("Change security/audit policy", "Change configuration")
        for outcome in ("success", "failure")
    },
    "AU-2.a.7": {
        ("Administrative/root access", outcome) for outcome in ("success", "failure")
    },
    "AU-2.a.8": {
        ("Elevate privilege/role", outcome) for outcome in ("success", "failure")
    },
    "AU-2.a.9": {
        ("Access audit/security logs", outcome) for outcome in ("success", "failure")
    },
    "AU-2.a.10": {
        (action, outcome)
        for action in ("Reboot", "Restart", "Shutdown")
        for outcome in ("success", "failure")
    },
    "AU-2.a.11": {
        ("Print to device", outcome) for outcome in ("success", "failure")
    },
    "AU-2.a.12": {
        ("Print to file", outcome) for outcome in ("success", "failure")
    },
    "AU-2.a.13": {
        ("Start application", outcome) for outcome in ("success", "failure")
    },
}


def fail(message: str) -> None:
    raise ValueError(message)


def parse_conf(path: pathlib.Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    with path.open(encoding="utf-8") as handle:
        parser.read_file(handle)
    return parser


def validate(root: pathlib.Path) -> list[str]:
    required = [
        root / "default/app.conf",
        root / "default/macros.conf",
        root / "default/data/ui/nav/default.xml",
        root / "default/data/ui/views/au2_linux_overview.xml",
        root / "lookups/au2_linux_event_catalog.csv",
        root / "metadata/default.meta",
        root / "README/README.txt",
        root / "default/data/ui/views/rhel_audit_verification.xml",
        root / "default/transforms.conf",
        root / "lookups/aulx_syscalls.csv",
        root / "lookups/aulx_action_catalog.csv",
        root / "lookups/aulx_verification_receipts.csv",
        root / "lookups/aulx_expected_sources.csv",
        root / "default/data/ui/views/rhel_review_readiness.xml",
        root / "bin/aulx_review.py",
        root / "bin/aulx_provenance.py",
        root / "README/REVIEW-GUIDE.txt",
        root / "README/RHEL-SOURCE-ONBOARDING.txt",
        root / "default/data/ui/views/setup.xml",
        root / "appserver/static/setup.js",
        root / "appserver/static/setup_core.js",
        root / "appserver/static/setup.css",
        root / "default/aulx_setup.conf",
    ]
    for path in required:
        if not path.is_file():
            fail(f"missing required file: {path.relative_to(root)}")

    app_conf = parse_conf(root / "default/app.conf")
    for section in ("install", "launcher", "ui", "package", "id"):
        if not app_conf.has_section(section):
            fail(f"app.conf missing [{section}]")
    if app_conf.get("package", "id") != root.name:
        fail("app.conf package id must match the app directory")
    if app_conf.get("ui", "setup_view") != "setup":
        fail("first-run setup view missing")
    setup = ET.parse(root / "default/data/ui/views/setup.xml").getroot()
    if setup.get("script") != "setup.js" or setup.findall(".//search"):
        fail("setup must load its JS adapter without automatic indexed searches")
    for name in ("setup-save", "setup-consent", "setup-preview", "setup-check", "setup-restore"):
        if setup.find(f".//*[@id='{name}']") is None:
            fail("missing setup control: " + name)

    macros = parse_conf(root / "default/macros.conf")
    for macro in ("aulx_source", "aulx_extract", "aulx_correlate", "aulx_session_context", "aulx_usb_session_context", "aulx_classify", "aulx_content", "aulx_events"):
        if not macros.has_option(macro, "definition"):
            fail(f"missing portable verification macro: {macro}")
    source = macros["aulx_source"]["definition"]
    if "index=*" not in source or re.search(r"\bhost\s*=", source) or "192.168." in source:
        fail("portable package must not contain a site-specific source override")
    usb = macros["aulx_usb"]["definition"]
    if 'sourcetype="linux:kernel:usb"' not in usb:
        fail("USB parser must be isolated to the collector-stamped USB sourcetype")
    if "coalesce(lx_journal_message,MESSAGE,_raw)" not in usb:
        fail("USB parser must support both structured journal JSON and plain forwarded kernel messages")
    if 'lx_usb_transport="kernel"' not in usb or "isnull(lx_usb_transport)" not in usb:
        fail("USB parser must enforce kernel transport when present and permit the exact plain-message source contract")
    if '"boot-identity-not-recorded"' not in usb:
        fail("USB correlation needs an explicit missing-boot boundary instead of a null BY field")
    rhel_view = root / "default/data/ui/views/rhel_audit_verification.xml"
    rhel_xml = ET.parse(rhel_view).getroot()
    tiles = [panel for panel in rhel_xml.findall(".//panel") if panel.get("id", "").startswith("tile_AU2_")]
    if len(tiles) != 57:
        fail("RHEL verification must show one tile for each of the 57 action/outcome cases")
    supplemental = [panel for panel in rhel_xml.findall(".//panel") if panel.get("id", "").startswith("tile_USB_")]
    if len(supplemental) != 2:
        fail("two supplemental USB tiles required, separate from the 57-case baseline")
    tiles += supplemental
    for panel in tiles[:57]:
        query = panel.findtext("table/search/query", "")
        if "Login_UID" not in query or "User not recorded" not in query:
            fail("baseline samples must preserve identity roles and explicit missing-user state")
    with (root / "lookups/aulx_expected_sources.csv").open() as stream:
        if list(csv.DictReader(stream)):
            fail("portable app must not ship lab/customer expected inventory")
    if any(panel.find("single/search").get("base") != "rhel_summary" for panel in tiles):
        fail("all case tiles must reuse the shared summary search")
    if any(panel.find("table/search") is None or panel.find("table/search").get("base") != "rhel_recent" for panel in tiles):
        fail("every event tile must include its latest-five sample table using the shared recent search")
    if any("sort 5 - event_time event_fingerprint" not in panel.findtext("table/search/query", "") for panel in tiles):
        fail("each sample must be limited to five in deterministic newest-first order")
    if len(rhel_xml.findall("search")) != 2:
        fail("exactly two indexed root search jobs required")
    if any(q.text.lstrip().startswith("`aulx_events`") for q in rhel_xml.findall(".//search/query")):
        fail("bare initial command macro causes Splunk Web to add a duplicate search keyword")
    if rhel_view.read_text().count("`aulx_events`") != 2:
        fail("RHEL dashboard must have two indexed event searches")
    with (root / "lookups/aulx_verification_receipts.csv").open() as stream:
        if list(csv.DictReader(stream)):
            fail("release package must not ship fabricated or customer-specific verified receipts")
    if "__au2_tag" in (root / "default/macros.conf").read_text():
        fail("double-underscore tag field was rejected by Splunk 10.4.3 live validation")
    if 'sourcetype="linux:secure"' not in macros["au2_linux_source"]["definition"]:
        fail("source macro must include the instance's linux:secure authentication sourcetype")
    classifier = macros["aulx_classify"]["definition"]
    if '"System boot observed; reboot cause and prior lifecycle sequence not established"' not in classifier:
        fail("native SYSTEM_BOOT alone must not assert a completed reboot")
    if 'audit_record_types,"^SYSTEM_SHUTDOWN$"' not in classifier:
        fail("native RHEL SYSTEM_SHUTDOWN must map to a shutdown candidate")
    extractor = macros["aulx_extract"]["definition"]
    if 'success|failed|failure|denied|yes|no|1|0' not in extractor:
        fail("extractor must support numeric and textual RHEL audit outcomes")
    if "lx_target_id" not in extractor or "operation=lx_op" not in extractor:
        fail("extractor must preserve native account target and operation context")
    required_macros = {
        "au2_linux_source",
        "au2_linux_normalize",
        "au2_linux_classify",
        "au2_linux_events",
    }
    missing_macros = required_macros.difference(macros.sections())
    if missing_macros:
        fail(f"missing macros: {sorted(missing_macros)}")
    for name in required_macros:
        if not macros.has_option(name, "definition"):
            fail(f"macro [{name}] has no definition")

    nav_root = ET.parse(root / "default/data/ui/nav/default.xml").getroot()
    view_root = ET.parse(root / "default/data/ui/views/au2_linux_overview.xml").getroot()
    if nav_root.tag != "nav":
        fail("navigation root must be <nav>")
    if view_root.tag != "form" or view_root.attrib.get("version") != "1.1":
        fail("dashboard must be a Simple XML 1.1 <form>")
    if not any(node.attrib.get("name") == "au2_linux_overview" for node in nav_root.findall("view")):
        fail("navigation does not reference the dashboard")

    dashboard_text = (root / "default/data/ui/views/au2_linux_overview.xml").read_text(encoding="utf-8")
    for macro in ("au2_linux_events",):
        if f"`{macro}`" not in dashboard_text:
            fail(f"dashboard does not reference `{macro}`")
    if dashboard_text.count("`au2_linux_events`") != 2:
        fail("dashboard must dispatch exactly two independent event searches")
    if re.search(r"refresh\s*=|<refresh>", dashboard_text):
        fail("dashboard must not auto-refresh")

    catalog_path = root / "lookups/au2_linux_event_catalog.csv"
    with catalog_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    expected_fields = {
        "record_id",
        "au2_requirement",
        "event_group",
        "event_action",
        "required_outcome",
        "linux_evidence_hint",
        "local_catalog",
        "test_id",
        "validation_state",
    }
    if set(rows[0]) != expected_fields:
        fail(f"catalog columns differ: {set(rows[0]).symmetric_difference(expected_fields)}")
    if len(rows) != 57:
        fail(f"catalog has {len(rows)} rows; expected 57")
    if len({row["record_id"] for row in rows}) != 57:
        fail("catalog record_id values are not unique")
    actual_requirements = {row["au2_requirement"] for row in rows}
    if actual_requirements != set(REQUIRED_OUTCOMES):
        fail("catalog does not contain exactly AU-2.a.1 through AU-2.a.13")
    for requirement, expected in REQUIRED_OUTCOMES.items():
        actual = {
            (row["event_action"], row["required_outcome"])
            for row in rows
            if row["au2_requirement"] == requirement
        }
        if actual != expected:
            fail(f"{requirement} case mismatch: expected {expected}, got {actual}")
    if {row["validation_state"] for row in rows} != {"Needs Validation"}:
        fail("all packaged cases must begin as Needs Validation")

    return [
        f"app={root.name}",
        f"catalog_rows={len(rows)}",
        f"requirements={len(actual_requirements)}",
        "independent_dashboard_searches=2",
        "validation=PASS",
    ]


def validate_archive(archive: pathlib.Path, expected_root: str) -> list[str]:
    with tarfile.open(archive, "r:gz") as handle:
        members = handle.getmembers()
        if not members:
            fail("archive is empty")
        for member in members:
            name = pathlib.PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts:
                fail(f"unsafe archive path: {member.name}")
            if name.parts[0] != expected_root:
                fail(f"archive member is outside {expected_root}: {member.name}")
            if any(part in {".DS_Store", "__MACOSX"} or part.startswith("._") for part in name.parts):
                fail(f"macOS metadata found in archive: {member.name}")
    return [f"archive={archive.name}", f"archive_members={len(members)}", "archive_validation=PASS"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("app_root", type=pathlib.Path)
    parser.add_argument("--archive", type=pathlib.Path)
    args = parser.parse_args()
    try:
        messages = validate(args.app_root.resolve())
        if args.archive:
            messages.extend(validate_archive(args.archive.resolve(), args.app_root.name))
    except (OSError, ValueError, configparser.Error, ET.ParseError, tarfile.TarError) as exc:
        print(f"validation=FAIL: {exc}", file=sys.stderr)
        return 1
    print("\n".join(messages))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
