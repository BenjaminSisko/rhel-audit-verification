/* Splunk Web adapter. All displayed data is rendered as text, never as HTML. */
require(['jquery', 'splunkjs/mvc', 'splunk.util', 'splunkjs/mvc/simplexml/ready!'], function ($, mvc, utils) {
    'use strict';
    const env = mvc.Components.get('env');
    const app = env.get('app');
    require([utils.make_url('/static/app/' + encodeURIComponent(app) + '/setup_core.js') + '?v=15008'], function (Core) {
        const service = mvc.createService({owner: 'nobody', app: app});
        function request(method, path, args) {
            return new Promise((resolve, reject) => {
                const timer = setTimeout(() => { const error = new Error('Splunk request exceeded 15 seconds. Do not retry blindly. Reload and inspect the backup/status.'); error.uncertain = method === 'POST'; reject(error); },15000);
                const operation = method === 'DELETE' ? 'del' : method.toLowerCase();
                service[operation](path, args, function (err, response) {
                    clearTimeout(timer);
                    if (err) { const error = new Error('Splunk request failed (' + (err.status || 'network/session') + '). Check permissions or sign in again. No automatic retry of writes.'); error.uncertain = method === 'POST' && (!err.status || err.status >= 500); reject(error); return; }
                    resolve(response.data);
                });
            });
        }
        const client = new Core.Client(request, app);
        const el = id => document.getElementById('setup-' + id);
        let initial, preview, suggestions = [], busy = false;
        function status(message, error) { el('status').textContent = message; el('status').className = error ? 'error' : ''; }
        function invalidate() { preview = null; el('consent').checked = false; el('preview-text').textContent = 'Draft changed. Preview again before saving.'; }
        async function run(message, task) {
            if (busy) return;
            busy = true; document.querySelectorAll('#aulx-setup button, #aulx-setup input, #aulx-setup select, #aulx-setup textarea').forEach(b => b.disabled = true); status(message);
            try { await task(); } catch (error) { status(error.message, true); }
            finally { busy = false; document.querySelectorAll('#aulx-setup button, #aulx-setup input, #aulx-setup select, #aulx-setup textarea').forEach(b => b.disabled = false); }
        }
        function table(target, rows, fields, selectable) {
            target.replaceChildren();
            const wrap = document.createElement('div'); wrap.className = 'setup-table-wrap';
            const t = document.createElement('table'), head = t.createTHead().insertRow();
            (selectable ? ['Select'].concat(fields) : fields).forEach(k => { const th = document.createElement('th'); th.scope = 'col'; th.textContent = k.replace(/_/g, ' '); head.appendChild(th); });
            const body = t.createTBody();
            rows.forEach((r,i) => {
                const tr = body.insertRow();
                if (selectable) { const input = document.createElement('input'); input.type = 'checkbox'; input.dataset.row = i; input.setAttribute('aria-label','Select ' + r.host + ' ' + r.sourcetype); tr.insertCell().appendChild(input); }
                fields.forEach(k => tr.insertCell().textContent = Array.isArray(r[k]) ? r[k].join('; ') : String(r[k] == null ? '' : r[k]));
            });
            wrap.appendChild(t); target.appendChild(wrap);
        }
        function download(name, value, type) {
            const url = URL.createObjectURL(new Blob([value], {type}));
            const a = document.createElement('a'); a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url),1000);
        }
        function id() { const bytes = new Uint8Array(16); crypto.getRandomValues(bytes); return Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join(''); }
        el('feeds').addEventListener('input', invalidate);
        window.addEventListener('beforeunload', event => { if (client.active) {event.preventDefault(); event.returnValue='';} });
        el('confirm-rhel').addEventListener('change', invalidate);
        el('discover').onclick = () => run('Looking for supported formats in your selected indexes…', async () => {
            const selected = el('manual-indexes').value.trim() ? el('manual-indexes').value.split(',').map(s=>s.trim()) : Array.from(el('indexes').selectedOptions, o=>o.value);
            suggestions = await client.discover(selected);
            table(el('discovery'), suggestions, ['host','index','sourcetype','format_hint','records'], true);
            const capped = suggestions.some(r => Number(r.sampled_records)>10000);
            status(suggestions.length ? 'Discovery finished: ' + suggestions.length + ' observed feeds. ' + (capped ? 'SAMPLE LIMIT REACHED; this is not a complete inventory. ' : '') + 'Confirm formats and Red Hat host identity; check feeds to add below.' : 'No records found in the selected 24 hours. Check index permissions, time and collection, or import an expected inventory.');
        });
        el('add').onclick = () => run('Updating your draft…', async () => {
            const selected = Array.from(el('discovery').querySelectorAll('input:checked'), e => suggestions[Number(e.dataset.row)]);
            if (!selected.length) throw new Error('Check one or more discovered feeds first.');
            let rows = el('feeds').value.trim() === Core.columns.join(',') ? [] : Core.parseCSV(el('feeds').value);
            for (const r of selected) {
                if (!rows.some(v => v.event_host===r.host && v.index===r.index && v.sourcetype===r.sourcetype)) rows.push({event_host:r.host,index:r.index,sourcetype:r.sourcetype,owner:el('owner').value,max_silence_seconds:el('silence').value,enabled:'1'});
            }
            el('feeds').value = Core.csv(Core.feeds(rows)); invalidate(); status('Draft updated. Nothing has been saved.');
        });
        el('csv-file').onchange = () => run('Reading your CSV locally…', async () => {
            const file = el('csv-file').files[0]; if (!file) return;
            if (file.size>150000) throw new Error('CSV exceeds 150 KB.');
            el('feeds').value = Core.csv(Core.parseCSV(await file.text())); invalidate(); status('CSV loaded into the draft. Review it before saving.');
        });
        el('template').onclick = () => download('expected-feeds-template.csv', Core.csv([{event_host:'rhel01.example.invalid',index:'rhel_audit',sourcetype:'linux:audit',owner:'Linux operations',max_silence_seconds:'3600',enabled:'1'}]), 'text/csv');
        el('preview').onclick = () => run('Checking the proposed configuration…', async () => {
            if (!initial) throw new Error('Existing configuration could not be loaded. Reload after resolving the error; nothing will be overwritten.');
            if (!el('confirm-rhel').checked) throw new Error('Confirm the enabled feeds belong to your intended Red Hat systems.');
            const rows = Core.parseCSV(el('feeds').value);
            const before = await client.snapshot();
            if (!Core.same(before,initial)) { initial = before; throw new Error('Saved configuration changed since opening setup. Reload the page to merge the latest inventory before proceeding.'); }
            preview = {before,rows}; el('consent').checked = false;
            el('preview-text').textContent = 'Expected feeds: ' + rows.length + '\n\nBEFORE — source scope:\n' + before.source.definition + '\n\nAFTER — source scope:\n' + Core.source(rows)
                + '\n\nCurrent inventory: ' + before.lookup.filename + '\nNew inventory: a unique app-owned CSV; old file retained.\nBackup: app configuration, created before save.\nNo endpoint, indexed-data, retention, permission or legacy-overview changes.';
            status(before.writable ? 'Preview ready. Review it, then explicitly approve Save configuration.' : 'Preview ready, but your account lacks write permission. Ask an authorized Splunk administrator to save.');
        });
        el('save').onclick = () => run('Saving with backup and read-back verification. Keep this page open…', async () => {
            if (!preview || !el('consent').checked || !el('confirm-rhel').checked) throw new Error('Prepare and approve an exact preview before saving.');
            if (!Core.same(Core.parseCSV(el('feeds').value),preview.rows)) throw new Error('Draft changed. Preview again.');
            el('check-results').replaceChildren();
            const operation = id(); el('backup-id').value = operation;
            const result = await client.save(preview.before,preview.rows,operation);
            initial = result.current; preview = null; el('consent').checked = false;
            status('Configuration saved and read back. Backup ID: ' + operation + '. Run Check saved setup next. No controls were marked accepted.');
        });
        el('restore').onclick = () => run('Restoring previous app settings…', async () => {
            if (!el('restore-consent').checked) throw new Error('Confirm restore before continuing.');
            el('check-results').replaceChildren();
            initial = await client.restore(el('backup-id').value.trim());
            el('feeds').value = Core.csv(initial.rows); invalidate(); el('restore-consent').checked = false;
            status('Previous app configuration restored and verified. Historical backup and inventory files retained.');
        });
        el('check').onclick = () => run('Checking saved configuration and recent feed presence…', async () => {
            const saved = await client.snapshot();
            if (!await client.effectiveScopeMatches(saved)) throw new Error('Your user-owned macro or lookup differs from the shared app configuration. Setup cannot certify the dashboard scope. Ask the administrator to reconcile the override; it was not changed.');
            if (saved.install.is_configured !== '1') throw new Error('Setup is not saved as configured. Preview and save first.');
            if (saved.source.definition !== Core.source(saved.rows)) throw new Error('Current scope differs from the wizard inventory. Use Review readiness for this custom configuration; no settings changed.');
            const result = await client.check(saved.rows);
            table(el('check-results'),result.rows,['event_host','index','sourcetype','records','status']);
            const content = await client.contentCheck(saved.rows);
            const details = document.createElement('pre');
            details.textContent = 'CONTENT SAMPLE — last 15 minutes, up to 1,001 raw records; partial audit groups are possible. Not a validation receipt.\n' + JSON.stringify(content,null,2);
            el('check-results').appendChild(details);
            const gaps = result.rows.filter(r=>!r.status.startsWith('Recent')).length;
            status('Setup checked under your current account. ' + gaps + ' feed(s) need investigation. ' + (result.sample_capped ? 'SAMPLE LIMIT REACHED; absence is inconclusive. ' : '') + 'Open Review readiness for event-content checks. This is not full event validation or analyst-role certification.');
        });
        run('Loading your current settings; no indexed discovery search yet…', async () => {
            initial = await client.snapshot();
            el('feeds').value = Core.csv(initial.rows);
            let indexMessage = '';
            try {
                const result = await client.api('GET','/services/data/indexes',{count:201});
                if ((result.entry||[]).length>200) indexMessage = 'Index list capped; enter exact names if needed. ';
                (result.entry||[]).slice(0,200).filter(e=>!e.name.startsWith('_')).forEach(e=>{ const o=document.createElement('option'); o.value=e.name; o.textContent=e.name; el('indexes').appendChild(o); });
            } catch (_) { indexMessage = 'Index listing is unavailable to this account; enter approved exact index names. '; }
            status(indexMessage + 'Existing settings loaded. ' + (initial.writable ? 'Choose indexes to discover, or import your expected feeds.' : 'Read-only account: an authorized administrator must save configuration.'));
        });
    });
});
