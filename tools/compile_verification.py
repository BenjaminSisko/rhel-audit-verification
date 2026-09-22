#!/usr/bin/env python3
"""Compile readable SPL sources and action catalog into the app package."""
import csv
import json
from pathlib import Path
import xml.etree.ElementTree as ET

project = Path(__file__).resolve().parents[1]
app = project / "package/TA_au2_linux"
macro_path = app / "default/macros.conf"
marker = "# BEGIN GENERATED PORTABLE VERIFICATION MACROS"
original = macro_path.read_text().split(marker)[0].rstrip()
parts = [original, marker]
for path in sorted((project / "searches").glob("aulx_*.spl")):
    spl = " ".join(line.strip() for line in path.read_text().splitlines())
    parts.append(f"[{path.stem}]\ndefinition = {spl}\niseval = 0")
parts.append("[aulx_events]\ndefinition = `aulx_source` | `aulx_extract` | `aulx_correlate` | `aulx_session_context` | `aulx_classify` | `aulx_content`\niseval = 0")
macro_path.write_text("\n\n".join(parts) + "\n")
with (app / "lookups/au2_linux_event_catalog.csv").open() as stream:
    catalog = list(csv.DictReader(stream))
with (app / "lookups/aulx_usb_catalog.csv").open() as stream:
    usb_catalog = list(csv.DictReader(stream))
actions = {r["event_action"]: {k: r[k] for k in ("event_action", "au2_requirement", "event_group")} for r in catalog}
with (app / "lookups/aulx_action_catalog.csv").open("w", newline="") as stream:
    writer = csv.DictWriter(stream, fieldnames=["event_action", "au2_requirement", "event_group"], lineterminator="\n")
    writer.writeheader()
    writer.writerows(actions.values())
print(f"Compiled {len(actions)} action definitions and portable verification macros")

# Native Simple XML tiles: all use one transforming base, not 57 index scans.
view_path = app / "default/data/ui/views/rhel_audit_verification.xml"
root = ET.parse(view_path).getroot()
root.set("stylesheet", "rhel_verification.css")
for query in root.findall(".//search/query"):
    if query.text.lstrip().startswith("`aulx_events`"):
        query.text = "| " + query.text.lstrip()
    query.text = query.text.replace('if(case_id!="UNMAPPED",case_id,null())', 'if(like(case_id,"AU2-%"),case_id,null())')
summary = root.find("search[@id='rhel_summary']/query")
if 'values(actor) AS users' not in summary.text:
    summary.text = summary.text.replace('values(native_kind) AS parser', 'values(native_kind) AS parser values(actor) AS users values(login_user) AS login_users values(process_user) AS process_users')
if 'inputlookup append=true aulx_usb_catalog.csv' not in summary.text:
    summary.text = summary.text.replace('| inputlookup au2_linux_event_catalog.csv |', '| inputlookup au2_linux_event_catalog.csv | inputlookup append=true aulx_usb_catalog.csv |')
for row in list(root.findall("row")):
    title = row.findtext("panel/table/title", "")
    if row.get("id", "").startswith("aulx_tiles_") or title.startswith("Each required AU-2 action/outcome"):
        root.remove(row)
old_init = root.find("init")
if old_init is not None:
    root.remove(old_init)
init = ET.Element("init")
root.insert(2, init)
old_recent = root.find("search[@id='rhel_recent']")
if old_recent is not None:
    root.remove(old_recent)
recent = ET.Element("search", id="rhel_recent")
ET.SubElement(recent, "query").text = """| `aulx_events`
| fillnull value="Unknown" event_host application case_id
| sort 0 - event_time event_fingerprint
| streamstats count AS sample_rank BY case_id event_host application
| where sample_rank<=5
| table case_id sample_rank event_time ingest_time event_host application event_action outcome actor login_user login_uid process_user process_uid effective_user effective_uid target_account identity_basis initiator completer source_ip terminal remote_access audit_session remote_access session_remote_access session_source_ip session_context_status session_context_basis session_context_fingerprints session_context_record_fingerprints object process_id privilege reason operation correlation_id event_fingerprint raw_records audit_record_types audit_keys syscall_name architecture usb_port usb_vendor usb_product_id usb_product usb_manufacturer usb_driver correlation_state missing_fields content_status verification_status index source sourcetype clock_status protection_status"""
ET.SubElement(recent, "earliest").text = "$time_tok.earliest$"
ET.SubElement(recent, "latest").text = "$time_tok.latest$"
root.insert(list(root).index(root.find("fieldset")), recent)
detail = next(table for table in root.findall(".//table") if table.findtext("title", "").startswith("Event evidence"))
detail_search = detail.find("search")
detail_search.clear()
detail_search.set("base", "rhel_recent")
ET.SubElement(detail_search, "query").text = """where ($host_tok|s$="*" OR event_host=$host_tok|s$) AND ($app_tok|s$="*" OR application=$app_tok|s$)
| sort 500 - event_time event_fingerprint
| fields - sample_rank"""
detail.find("title").text = "Event evidence — recent samples with full extracted content and gaps"
for paragraph in root.findall(".//html/p"):
    if (paragraph.text or "").startswith("Detail shows at most"):
        paragraph.text = "Each tile shows up to five most recent matching correlated events, newest first, in the selected time/host/application scope. The shared sample search retains five per case/host/application; the detail table shows at most 500 of those samples, not a complete export. Counts come from the separate full-window summary, subject to Splunk search limits. One event can match multiple categories. Missing counterpart records, time skew, truncation or search warnings invalidate completeness assumptions."
source_row = next(row for row in root.findall("row") if row.findtext("panel/table/title", "").startswith("Source / application health"))
insert_at = list(root).index(source_row)
grouped = {}
for case in usb_catalog + catalog:
    grouped.setdefault(case["au2_requirement"], []).append(case)
for group_index, (requirement, cases) in enumerate(grouped.items(), 1):
    header_row = ET.Element("row", id=f"aulx_tiles_header_{group_index}")
    html = ET.SubElement(ET.SubElement(header_row, "panel"), "html")
    ET.SubElement(html, "h2").text = f"{requirement} · {cases[0]['event_group']}"
    ET.SubElement(html, "p").text = ("Supplemental device observations, excluded from the 57-case AU-2 coverage score. Attachment means the kernel found a device, not that storage was usable or a file was transferred. Physical user identity is not recorded by these messages; missing AU-3 content stays visible. USB context joins only the same boot/port/device sequence within five seconds and the selected window."
        if requirement == "Supplemental" else "Each tile is one required action/outcome. Session origin/source are correlated login context, not direct event fields or proof of a network operation. Boot continuity requires review; missing evidence remains visible.")
    root.insert(insert_at, header_row)
    insert_at += 1
    for offset in range(0, len(cases), 3):
        row = ET.Element("row", id=f"aulx_tiles_{group_index}_{offset}")
        for case in cases[offset:offset + 3]:
            key = case["record_id"]
            token = "tile_" + key.replace("-", "_")
            panel = ET.SubElement(row, "panel", id=token)
            ET.SubElement(panel, "title").text = f"{case['event_action']} · " + ("OBSERVED" if requirement == "Supplemental" else case['required_outcome'].upper())
            single = ET.SubElement(panel, "single")
            search = ET.SubElement(single, "search", base="rhel_summary")
            query = ('search case_id=' + json.dumps(key) + ' | where record_kind="expected" OR (($host_tok|s$="*" OR event_host=$host_tok|s$) AND ($app_tok|s$="*" OR application=$app_tok|s$))'
                     ' | stats sum(matched_events) AS n sum(all_complete) AS complete values(missing_fields) AS missing_fields values(verification_status) AS statuses max(last_event) AS last_event'
                     ' | eval value=coalesce(n,0), complete=coalesce(complete,0)'
                     ' | eval capture=if(value=0,"No matching evidence","Captured candidate"), content=case(value=0,"Not testable — no event",complete=value,"Required fields present — review needed",true(),"Missing required content"), verification=if(mvfind(statuses,"^Verified test receipt$")>=0,"Reviewed test receipt exists","Not yet verified"), missing=if(value=0,"No source record to inspect",mvjoin(missing_fields,", ")), last_seen=if(isnull(last_event),"None in selected window",strftime(last_event,"%Y-%m-%d %H:%M:%S %Z"))'
                     ' | fields value capture content verification missing last_seen users login_users process_users')
            query = query.replace('values(missing_fields) AS missing_fields', 'values(users) AS users values(login_users) AS login_users values(process_users) AS process_users values(missing_fields) AS missing_fields')
            ET.SubElement(search, "query").text = query
            done = ET.SubElement(search, "done")
            for field in ("capture", "content", "verification", "missing", "last_seen"):
                ET.SubElement(init, "set", token=token + "_" + field).text = "Waiting for search"
                ET.SubElement(done, "set", token=token + "_" + field).text = "$result." + field + "$"
            for name, value in (("underLabel", "captured candidate matches"), ("drilldown", "none"), ("numberPrecision", "0"), ("useColors", "0")):
                ET.SubElement(single, "option", name=name).text = value
            html = ET.SubElement(panel, "html")
            block = ET.SubElement(html, "div", {"class": "audit-tile-status"})
            for field, label in (("capture", "Capture"), ("content", "AU-3 + application content"), ("verification", "Verification"), ("last_seen", "Last event"), ("missing", "Missing information")):
                paragraph = ET.SubElement(block, "p")
                bold = ET.SubElement(paragraph, "strong")
                bold.text = label + ": "
                bold.tail = "$" + token + "_" + field + "$"
            table = ET.Element("table")
            panel.insert(2, table)  # Keep the count and newest samples adjacent.
            ET.SubElement(table, "title").text = "Latest 5 matching events • newest first"
            sample_search = ET.SubElement(table, "search", base="rhel_recent")
            ET.SubElement(sample_search, "query").text = ('search case_id=' + json.dumps(key)
                + ' | where ($host_tok|s$="*" OR event_host=$host_tok|s$) AND ($app_tok|s$="*" OR application=$app_tok|s$)'
                + ' | sort 5 - event_time event_fingerprint'
                + ' | eval Time=strftime(event_time,"%Y-%m-%d %H:%M:%S %Z"), User=coalesce(mvjoin(actor,", "),"User not recorded"), Login=coalesce(mvjoin(login_user,", "),"Not recorded"), Login_UID=coalesce(mvjoin(login_uid,", "),"Not recorded"), Process=coalesce(mvjoin(process_user,", "),"Not recorded"), Effective=coalesce(mvjoin(effective_user,", "),"Not recorded"), Account=coalesce(mvjoin(target_account,", "),"Not recorded")'
                + ' | rename event_host AS Host application AS Application'
                + ' | eval User=User.if(Login!="Not recorded" AND NOT in(Login_UID,"4294967295","-1","Not recorded")," (login UID ".Login_UID.")","")'
                + ' | eval Session_origin=coalesce(session_remote_access,"Not established"), Session_source=coalesce(session_source_ip,"Not established")'
                + ' | table Time User Process Host Application Session_origin Session_source')
            for name, value in (("count", "5"), ("wrap", "true"), ("drilldown", "none"), ("rowNumbers", "false")):
                ET.SubElement(table, "option", name=name).text = value
            if requirement == "Supplemental":
                sample_search.find("query").text = sample_search.find("query").text.replace(' | table Time User Process Host Application Session_origin Session_source', ' | rename object AS Device | table Time User Host Application Device')
        root.insert(insert_at, row)
        insert_at += 1
ET.indent(root, space="  ")
view_path.write_text(ET.tostring(root, encoding="unicode") + "\n")
print("Generated 57 AU-2 tiles plus 2 supplemental USB tiles across 14 sections")

# Splunk Web prepends 'search' to bare macro queries. These source macros
# already expand to a search command, so use an explicit leading pipeline.
legacy_path = app / "default/data/ui/views/au2_linux_overview.xml"
legacy = ET.parse(legacy_path).getroot()
for query in legacy.findall(".//search/query"):
    if query.text.lstrip().startswith(("`au2_linux_source`", "`au2_linux_events`")):
        query.text = "| " + query.text.lstrip()
ET.indent(legacy, space="  ")
legacy_path.write_text(ET.tostring(legacy, encoding="unicode") + "\n")
