/* Pure setup logic and bounded REST workflow. No credentials or indexed writes. */
(function (root, factory) {
    if (typeof module === 'object' && module.exports) module.exports = factory();
    else if (typeof define === 'function' && define.amd) define([], factory);
    else root.AulxSetup = factory();
}(this, function () {
    'use strict';
    const columns = ['event_host', 'index', 'sourcetype', 'owner', 'max_silence_seconds', 'enabled'];
    const maxFeeds = 200, sampleLimit = 10000;
    function truth(v) { return v === true || v === 1 || v === '1' || v === 'true'; }
    function warnings(messages) {
        if (!messages) return false;
        if (Array.isArray(messages)) return messages.some(warnings);
        if (typeof messages === 'object') return /WARN|ERROR|FATAL/.test(messages.type || '') || Object.entries(messages).some(([k,v]) => /WARN|ERROR|FATAL/.test(k) || (typeof v === 'object' && warnings(v)));
        return false;
    }
    function fail(message) { throw new Error(message); }
    function literal(value) { return JSON.stringify(String(value)); }
    function identity(value, label) {
        const s = String(value || '').trim();
        if (!/^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,199}$/.test(s)) fail(label + ': use an exact name (letters, numbers, . _ : @ / -), not a wildcard or SPL.');
        return s;
    }
    function indexes(values) {
        if (!Array.isArray(values) || !values.length || values.length > 5) fail('Select between one and five indexes.');
        return [...new Set(values.map(v => identity(v, 'Index')))];
    }
    function feeds(values) {
        if (!Array.isArray(values) || !values.length || values.length > maxFeeds) fail('Provide between one and 200 expected feeds.');
        const seen = new Set();
        const result = values.map(row => {
            const out = {};
            ['event_host', 'index', 'sourcetype'].forEach(k => out[k] = identity(row[k], k));
            out.owner = String(row.owner || '').trim();
            if (!out.owner || out.owner.length > 120 || /[\x00-\x1f\x7f`]/.test(out.owner)) fail('Each feed needs an owner, at most 120 characters, without control characters or backticks.');
            const n = String(row.max_silence_seconds || '');
            if (!/^\d+$/.test(n) || Number(n) < 60 || Number(n) > 2592000) fail('Silence threshold must be 60–2592000 seconds.');
            out.max_silence_seconds = String(Number(n));
            out.enabled = String(row.enabled);
            if (!['0', '1'].includes(out.enabled)) fail('Enabled must be 0 or 1.');
            const key = JSON.stringify([out.event_host, out.index, out.sourcetype]);
            if (seen.has(key)) fail('Duplicate host/index/sourcetype feed.');
            seen.add(key);
            return out;
        });
        if (!result.some(r => r.enabled === '1')) fail('Enable at least one expected feed.');
        return result.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
    }
    function parseCSV(text) {
        if (text.length > 150000) fail('CSV exceeds 150 KB.');
        text = text.replace(/^\uFEFF/, '');
        const rows = []; let row = [], cell = '', quoted = false, closed = false;
        for (let i = 0; i < text.length; i++) {
            const c = text[i];
            if (quoted) {
                if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; }
                else if (c === '"') { quoted = false; closed = true; }
                else cell += c;
            } else if (c === '"' && cell === '' && !closed) quoted = true;
            else if (c === ',' || c === '\n' || c === '\r') {
                row.push(cell); cell = ''; closed = false;
                if (c !== ',') {
                    if (c === '\r' && text[i + 1] === '\n') i++;
                    if (row.some(v => v !== '')) rows.push(row);
                    row = [];
                }
            } else { if (closed || c === '"') fail('Malformed CSV quoting.'); cell += c; }
        }
        if (quoted) fail('Unclosed CSV quote.');
        if (cell || row.length) { row.push(cell); rows.push(row); }
        if (!rows.length || JSON.stringify(rows.shift()) !== JSON.stringify(columns)) fail('CSV header must be: ' + columns.join(','));
        return feeds(rows.map(r => {
            if (r.length !== columns.length) fail('CSV row has the wrong number of columns.');
            return Object.fromEntries(columns.map((k, i) => [k, r[i]]));
        }));
    }
    function csv(rows) {
        const escape = v => '"' + String(v).replace(/"/g, '""') + '"';
        return columns.join(',') + '\n' + rows.map(r => columns.map(k => escape(r[k])).join(',')).join('\n') + '\n';
    }
    function source(rows) {
        return 'search (' + feeds(rows).filter(r => r.enabled === '1').map(r =>
            '(index=' + literal(r.index) + ' host=' + literal(r.event_host) + ' sourcetype=' + literal(r.sourcetype) + ')').join(' OR ') + ')';
    }
    function discovery(selected) {
        return 'search (' + indexes(selected).map(v => 'index=' + literal(v)).join(' OR ') + ')'
            + ' | head 10001 | eval setup_raw=coalesce(full_log,_raw)'
            + ' | eval format_hint=case(match(setup_raw,"type=[A-Z_]+ .*audit[(]"),"auditd candidate",'
            + 'match(setup_raw,"sshd|pam_unix"),"authentication candidate",'
            + 'sourcetype="linux:kernel:usb","USB collector contract — inspect source",'
            + 'sourcetype="linux_app_audit","application JSON contract — inspect source",true(),"Unrecognized — inspect source")'
            + ' | eventstats count AS sampled_records | stats count AS records max(_time) AS last_seen values(format_hint) AS format_hint max(sampled_records) AS sampled_records BY host index sourcetype';
    }
    function checkQuery(rows) {
        return source(rows) + ' | head 10001 | eval event_host=host'
            + ' | stats count AS records max(_time) AS last_seen BY event_host index sourcetype';
    }
    function inventoryQuery(rows, filename) {
        if (!/^aulx_setup_[0-9a-f]{32}\.csv$/.test(filename)) fail('Invalid generated lookup filename.');
        // A JSON eval literal avoids command-argument CSV newline interpretation.
        // Names and owners reject backticks; all JSON quotes/backslashes are escaped.
        return '| makeresults | eval payload=' + literal(JSON.stringify({rows:feeds(rows)}))
            + ' | spath input=payload path=rows{} output=setup_row | mvexpand setup_row | spath input=setup_row'
            + ' | fields ' + columns.join(' ') + ' | outputlookup createinapp=true override_if_empty=false ' + filename;
    }
    function same(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
    function recognized(row) {
        const hints = Array.isArray(row.format_hint) ? row.format_hint : [row.format_hint];
        return hints.length > 0 && hints.every(v => ['auditd candidate', 'authentication candidate',
            'USB collector contract — inspect source', 'application JSON contract — inspect source'].includes(v));
    }
    function expressRows(existing, selected, owner, silence) {
        if (!Array.isArray(selected) || !selected.length) fail('Select at least one recognized feed. Use Advanced setup for other formats.');
        const rows = existing.map(r => Object.assign({},r));
        for (const r of selected) {
            if (!recognized(r)) fail('Express setup cannot add an unrecognized or mixed-format feed. Inspect it in Advanced setup.');
            const added = {event_host:r.host, index:r.index, sourcetype:r.sourcetype, owner,
                max_silence_seconds:String(silence), enabled:'1'};
            // Validate candidates even if an existing tuple will win. Never re-enable a
            // disabled feed or replace its owner/threshold because discovery found it.
            feeds([added]);
            if (!rows.some(v => v.event_host === r.host && v.index === r.index && v.sourcetype === r.sourcetype)) rows.push(added);
        }
        return feeds(rows);
    }
    function backupId(snapshot) {
        const match = /^aulx_setup_([0-9a-f]{32})\.csv$/.exec(snapshot.lookup.filename);
        return match ? match[1] : '';
    }
    class Client {
        constructor(request, app, sleep) {
            this.request = request;
            this.app = identity(app, 'App');
            this.base = '/servicesNS/nobody/' + encodeURIComponent(app) + '/';
            this.sleep = sleep || (ms => new Promise(resolve => setTimeout(resolve, ms)));
            this.active = false;
        }
        async api(method, path, args) {
            // The app-management endpoint updates the same app.conf flag AND the
            // app manager's effective state. Writing only conf-app left Splunk Web
            // redirecting to first-run setup in the live navigation test.
            // Keep the logical backup path compatible with 1.5.0 backups.
            const install = path === 'configs/conf-app/install';
            const parameters = Object.assign({output_mode:'json'},args);
            if (install && Object.prototype.hasOwnProperty.call(parameters,'is_configured')) {
                parameters.configured=parameters.is_configured; delete parameters.is_configured;
            }
            let endpoint = install ? '/services/apps/local/'+encodeURIComponent(this.app) : path.startsWith('/') ? path : this.base + path;
            // This handler rejects output_mode as an app property. The Splunk
            // SDK adapter already negotiates JSON in the URL for every request.
            if (install && method==='POST') delete parameters.output_mode;
            const data = await this.request(method, endpoint, parameters);
            if (install) for (const entry of data.entry || []) entry.content.is_configured=String(Number(truth(entry.content.configured)));
            const messages = data.messages || [];
            if (messages.some(m => ['ERROR', 'FATAL', 'WARN'].includes(m.type))) fail(messages.map(m => m.text).join('; '));
            return data;
        }
        async entry(path) {
            const result = await this.api('GET', path, {count: 1});
            if (!result.entry || result.entry.length !== 1) fail('Expected one configuration entry: ' + path);
            return result.entry[0];
        }
        async search(query, earliest) {
            let sid;
            try {
                const job = await this.api('POST', 'search/jobs', {search: query, earliest_time: earliest || '-24h', latest_time: 'now', max_time: 25, auto_cancel: 30, exec_mode: 'normal'});
                sid = job.sid;
                if (!/^[A-Za-z0-9_.-]+$/.test(sid || '')) fail('Invalid search job response.');
                const start = Date.now();
                for (let attempt = 0; attempt < 65; attempt++) {
                    const state = (await this.entry('search/jobs/' + sid)).content;
                    if (truth(state.isFailed) || truth(state.isFinalized) || ['FAILED', 'BAD_INPUT_CANCEL'].includes(state.dispatchState)) fail('Search failed or was finalized early; no setup pass can be asserted.');
                    if (truth(state.isDone)) {
                        if (Number(state.resultCount) > 1000) fail('Result limit exceeded; narrow scope.');
                        if (warnings(state.messages)) fail('Search returned warnings; inspect it in Splunk before continuing.');
                        const result = await this.api('GET', 'search/jobs/' + sid + '/results', {count: 1001});
                        if (truth(result.preview) || !Array.isArray(result.results) || result.results.length > 1000) fail('Incomplete search results.');
                        return result.results;
                    }
                    if (Date.now() - start > 32000) fail('Search timed out. Narrow the selected scope.');
                    await this.sleep(500);
                }
                fail('Search polling limit reached.');
            } finally {
                if (sid) { try { await this.api('DELETE', 'search/jobs/' + sid); } catch (_) { /* auto_cancel is a second bound */ } }
            }
        }
        async snapshot() {
            const macro = await this.entry('configs/conf-macros/aulx_source');
            const transform = await this.entry('configs/conf-transforms/aulx_expected_sources');
            const install = await this.entry('configs/conf-app/install');
            if (!transform.content.filename || transform.content.external_type) fail('The wizard supports CSV expected-feed lookups only; preserve this custom configuration and use the manual guide.');
            const rows = await this.search('| inputlookup strict=true aulx_expected_sources | head 201 | fields ' + columns.join(' '));
            if (rows.length > maxFeeds) fail('Existing inventory exceeds 200 feeds. Use managed deployment; no settings changed.');
            return {
                source: {definition: macro.content.definition, iseval: String(Number(truth(macro.content.iseval)))},
                lookup: {filename: transform.content.filename},
                install: {is_configured: String(Number(truth(install.content.is_configured)))},
                rows: rows.map(r => Object.fromEntries(columns.map(k => [k, String(r[k] == null ? '' : r[k])]))).sort((a,b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
                writable: !!(macro.acl && truth(macro.acl.can_write) && transform.acl && truth(transform.acl.can_write) && install.acl && truth(install.acl.can_write))
            };
        }
        async discover(selected) { return this.search(discovery(selected)); }
        async effectiveScopeMatches(shared) {
            const current = await this.entry('/services/authentication/current-context');
            const user = current.content.username;
            if (typeof user !== 'string' || !user) fail('Cannot verify current search identity.');
            const macro = await this.entry('/servicesNS/' + encodeURIComponent(user) + '/' + encodeURIComponent(this.app) + '/configs/conf-macros/aulx_source');
            const lookup = await this.entry('/servicesNS/' + encodeURIComponent(user) + '/' + encodeURIComponent(this.app) + '/configs/conf-transforms/aulx_expected_sources');
            return macro.content.definition === shared.source.definition && lookup.content.filename === shared.lookup.filename;
        }
        async check(rows) {
            const expected = feeds(rows).filter(r => r.enabled === '1');
            const observed = await this.search(checkQuery(expected));
            const total = observed.reduce((n, r) => n + Number(r.records), 0);
            const now = Date.now()/1000;
            return {sample_capped: total > sampleLimit, rows: expected.map(r => {
                const found = observed.find(v => v.event_host === r.event_host && v.index === r.index && v.sourcetype === r.sourcetype);
                return Object.assign({}, r, {status: !found ? 'No records in the checked 24 hours — investigate' : now-Number(found.last_seen) > Number(r.max_silence_seconds) ? 'Records found, older than your silence threshold' : 'Recent records found — content validation still required', records: found ? found.records : '0'});
            })};
        }
        async contentCheck(rows) {
            return this.search(source(rows) + ' | head 1001 | `aulx_extract` | `aulx_correlate` | `aulx_session_context` | `aulx_usb_session_context` | `aulx_classify` | `aulx_content`'
                + ' | stats dc(event_key) AS unique_sampled_events count AS category_rows sum(field_check_complete) AS category_rows_with_all_fields values(missing_fields) AS content_gaps values(native_kind) AS recognized_parsers', '-15m');
        }
        async record(id, data) {
            return this.api('POST', 'configs/conf-aulx_setup', {name: id, snapshot: JSON.stringify(data)});
        }
        async save(before, rows, id) {
            if (this.active) fail('A setup operation is already running.');
            if (!/^[0-9a-f]{32}$/.test(id)) fail('Invalid operation ID.');
            const expected = feeds(rows), filename = 'aulx_setup_' + id + '.csv';
            if (!before.writable) fail('An authorized Splunk administrator must save these settings.');
            this.active = true;
            const paths = ['configs/conf-macros/aulx_source', 'configs/conf-transforms/aulx_expected_sources', 'configs/conf-app/install'];
            const previous = [before.source, before.lookup, before.install];
            const after = [{definition: source(expected), iseval: '0'}, {filename}, {is_configured: '1'}];
            const changed = [];
            try {
                if (!same(await this.snapshot(), before)) fail('Configuration changed since preview. Reload before saving.');
                // Keep an app-scoped server-side backup before the first configuration write.
                await this.record('backup_' + id, {schema: 1, created_utc: new Date().toISOString(), before, after, paths, expected});
                await this.search(inventoryQuery(expected, filename));
                const written = await this.search('| inputlookup strict=true ' + filename + ' | fields ' + columns.join(' '));
                if (!same(feeds(written), expected)) fail('New inventory read-back did not match. Existing configuration was not changed.');
                if (!same(await this.snapshot(), before)) fail('Configuration changed during save. Existing scope was not replaced.');
                for (let i=0; i<paths.length; i++) {
                    const guard = (await this.entry(paths[i])).content;
                    if (!Object.keys(previous[i]).every(k => String(guard[k]) === String(previous[i][k]))) fail('Concurrent configuration change; save stopped.');
                    // Include uncertain writes in rollback; a timeout may happen after commit.
                    changed.push(i);
                    await this.api('POST', paths[i], after[i]);
                    const entry = (await this.entry(paths[i])).content;
                    if (!Object.keys(after[i]).every(k => String(entry[k]) === String(after[i][k]))) fail('Configuration read-back failed.');
                }
                const current = await this.snapshot();
                if (current.source.definition !== after[0].definition || current.lookup.filename !== filename || !same(feeds(current.rows), expected)) fail('Final configuration verification failed.');
                await this.record('complete_' + id, {verified_utc: new Date().toISOString(), lookup: filename, feeds: expected.length});
                return {id, current};
            } catch (error) {
                const failures = [];
                for (const i of changed.reverse()) {
                    try {
                        const live = (await this.entry(paths[i])).content;
                        const equal = value => Object.keys(value).every(k => String(live[k]) === String(value[k]));
                        if (equal(previous[i])) continue;
                        if (!equal(after[i])) fail('Concurrent change; not overwritten');
                        await this.api('POST', paths[i], previous[i]);
                        const restored = (await this.entry(paths[i])).content;
                        if (!Object.keys(previous[i]).every(k => String(restored[k]) === String(previous[i][k]))) fail('Rollback read-back mismatch');
                    } catch (_) { failures.push(paths[i]); }
                }
                fail(error.message + (failures.length ? ' Recovery needed: ' + failures.join(', ') + '. Backup: backup_' + id : error.uncertain ? ' A write outcome is uncertain; a late write is possible even after rollback checks. Reload and inspect backup_' + id + ' before proceeding.' : ' Previous configuration retained/restored. New backup/inventory files are retained for review.'));
            } finally { this.active = false; }
        }
        async restore(id) {
            if (this.active) fail('A setup operation is already running.');
            if (!/^[0-9a-f]{32}$/.test(id)) fail('Invalid backup ID.');
            const backup = JSON.parse((await this.entry('configs/conf-aulx_setup/backup_' + id)).content.snapshot);
            const current = await this.snapshot();
            if (!current.writable) fail('Administrator write permission is required.');
            if (backup.schema !== 1 || backup.paths.length !== 3 || !same(backup.paths, ['configs/conf-macros/aulx_source', 'configs/conf-transforms/aulx_expected_sources', 'configs/conf-app/install'])) fail('Invalid backup schema.');
            if (!same(current.source, backup.after[0]) || !same(current.lookup, backup.after[1]) || !same(current.install, backup.after[2])) fail('Settings changed after this setup. Restore stopped to preserve those changes.');
            if (!same(feeds(current.rows), feeds(backup.expected))) fail('Saved inventory changed after setup. Restore stopped to preserve those changes.');
            this.active = true;
            try {
                // Restore only these three fields; the original CSV was never overwritten.
                for (const i of [2,1,0]) await this.api('POST', backup.paths[i], [backup.before.source,backup.before.lookup,backup.before.install][i]);
                const restored = await this.snapshot();
                if (!same(restored, backup.before)) fail('Restore read-back differs; administrator review needed.');
                await this.record('restored_' + id, {verified_utc: new Date().toISOString()});
                return restored;
            } catch (error) {
                fail('Restore did not complete cleanly. Reload and have an administrator compare backup_' + id + ' with current settings; do not assume either configuration is active. ' + error.message);
            } finally { this.active = false; }
        }
    }
    return {columns, feeds, parseCSV, csv, source, discovery, checkQuery, inventoryQuery, Client, same, recognized, expressRows, backupId};
}));
