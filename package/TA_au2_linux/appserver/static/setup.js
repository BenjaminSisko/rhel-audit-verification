/* Splunk Web adapter. All displayed data is rendered as text, never as HTML. */
require(['jquery', 'splunkjs/mvc', 'splunk.util', 'splunkjs/mvc/simplexml/ready!'], function ($, mvc, utils) {
    'use strict';
    const env = mvc.Components.get('env');
    const app = env.get('app');
    require([utils.make_url('/static/app/' + encodeURIComponent(app) + '/setup_core.js') + '?v=15104'], function (Core) {
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
        let initial, preview, expressPreview, suggestions = [], busy = false, mode = 'express';
        function status(message, error) { el('status').textContent = message; el('status').className = error ? 'error' : ''; }
        function invalidateExpress() { expressPreview = null; el('express-consent').checked = false; el('express-summary').textContent = 'Selection changed. Review again before Finish.'; el('express-feeds').replaceChildren(); el('express-diff').textContent = 'No current preview.'; }
        function invalidate() { preview = null; el('consent').checked = false; el('preview-text').textContent = 'Draft changed. Preview again before saving.'; invalidateExpress(); }
        function restoreSummary() {
            const value = initial && Core.backupId(initial);
            el('restore-summary').textContent = value ? 'A backup is associated with your current wizard inventory. Restore verifies it before changing settings; no backup ID entry needed.' : 'This configuration has no current wizard backup. You can use a previously recorded backup ID below.';
            el('restore-current-consent').checked = false;
        }
        function setMode(value) {
            mode = value; invalidate();
            el('advanced').hidden = value !== 'advanced'; el('express').hidden = value !== 'express';
            for (const v of ['express','advanced']) { el('mode-'+v).setAttribute('aria-pressed',String(value===v)); el('mode-'+v).classList.toggle('setup-primary',value===v); }
            el('mode-description').textContent = value === 'express' ? 'Express: find logs, review your selection, then Finish. Existing expected feeds are retained.' : 'Advanced: add discovered feeds, import or edit inventory, preview and save. Use this for silent hosts or custom selections.';
        }
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
                if (selectable) { const input = document.createElement('input'); input.type = 'checkbox'; input.dataset.row = i; input.checked = mode === 'express' && Core.recognized(r); input.setAttribute('aria-label','Select ' + r.host + ' ' + r.sourcetype); tr.insertCell().appendChild(input); }
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
        el('mode-express').onclick = () => setMode('express');
        el('mode-advanced').onclick = () => setMode('advanced');
        el('discovery').addEventListener('change',invalidateExpress);
        for (const v of ['express-owner','express-silence']) el(v).addEventListener('input',invalidateExpress);
        for (const v of ['indexes','manual-indexes']) el(v).addEventListener('change',()=>{suggestions=[];el('discovery').replaceChildren();invalidateExpress();});
        window.addEventListener('beforeunload', event => { if (client.active) {event.preventDefault(); event.returnValue='';} });
        el('confirm-rhel').addEventListener('change', invalidate);
        el('discover').onclick = () => run('Looking for supported formats in your selected indexes…', async () => {
            suggestions=[]; el('discovery').replaceChildren(); invalidateExpress();
            const selected = el('manual-indexes').value.trim() ? el('manual-indexes').value.split(',').map(s=>s.trim()) : Array.from(el('indexes').selectedOptions, o=>o.value);
            suggestions = await client.discover(selected);
            table(el('discovery'), suggestions, ['host','index','sourcetype','format_hint','records'], true);
            const capped = suggestions.some(r => Number(r.sampled_records)>10000);
            status(suggestions.length ? 'Discovery finished: ' + suggestions.length + ' observed feeds. ' + (capped ? 'SAMPLE LIMIT REACHED; this is not a complete inventory. ' : '') + 'Confirm formats and Red Hat host identity; recognized feeds are suggested in Express.' : 'No records found in the selected 24 hours. Check index permissions, time and collection, or import an expected inventory.');
        });
        function selectedFeeds() { return Array.from(el('discovery').querySelectorAll('input:checked'), e => suggestions[Number(e.dataset.row)]); }
        function expressDraft() { return Core.expressRows(initial.rows,selectedFeeds(),el('express-owner').value,el('express-silence').value); }
        el('express-review').onclick = () => run('Preparing your Express configuration…',async()=>{
            if (!initial) throw new Error('Existing configuration is unavailable. Reload before making changes.');
            const rows = expressDraft(), before = await client.snapshot();
            if (!Core.same(before,initial)) throw new Error('Configuration changed since opening setup. Reload to merge the current inventory.');
            expressPreview = {before,rows}; el('express-consent').checked=false;
            const added = rows.length - initial.rows.length, enabled = rows.filter(r=>r.enabled==='1').length;
            const capped = suggestions.some(r=>Number(r.sampled_records)>10000);
            el('express-summary').textContent = 'Ready to configure '+enabled+' enabled feeds on '+new Set(rows.filter(r=>r.enabled==='1').map(r=>r.event_host)).size+' hosts.\n'+added+' new feeds; '+initial.rows.length+' existing feeds retained, including silent/disabled entries.\n'+(capped?'Discovery sample limit reached. ':'')+'Complete fleet coverage is NOT established by discovery. Review every enabled feed below.';
            table(el('express-feeds'),rows,Core.columns);
            el('express-diff').textContent='BEFORE\n'+before.source.definition+'\n\nAFTER\n'+Core.source(rows)+'\n\nA backup and new inventory file are created; the old file is retained. Only app search scope, inventory binding and setup-complete flag change.';
            status(before.writable?'Express preview ready. Confirm your scope and click Finish and check.':'Read-only preview. An authorized Splunk administrator must finish setup.');
        });
        el('finish').onclick = () => run('Saving Express settings with a backup. Keep this page open…',async()=>{
            if (!expressPreview || !el('express-consent').checked) throw new Error('Review and confirm the Express selection before Finish.');
            if (!Core.same(expressDraft(),expressPreview.rows)) throw new Error('Selection changed. Review again.');
            el('check-results').replaceChildren();
            const operation=id(); el('backup-id').value=operation;
            const result=await client.save(expressPreview.before,expressPreview.rows,operation);
            initial=result.current; el('feeds').value=Core.csv(initial.rows); invalidate(); restoreSummary();
            el('express-summary').textContent='Settings saved and read back. Backup ID: '+operation+'. Checking recent logs now…';
            // Save success must remain distinct from a failed or incomplete follow-up check.
            try { await checkSaved(); el('express-summary').textContent='Settings saved and read back. Setup checks finished; review the results below. No controls marked accepted.'; }
            catch(error) { el('express-summary').textContent='Settings saved and read back. Follow-up checks could not finish. Your configuration remains saved; use Check saved setup to retry checks or Restore previous settings.'; throw new Error('Configuration SAVED; checks incomplete: '+error.message); }
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
            restoreSummary();
            status('Configuration saved and read back. Backup ID: ' + operation + '. Run Check saved setup next. No controls were marked accepted.');
        });
        async function restoreSettings(operation) {
            el('check-results').replaceChildren();
            initial = await client.restore(operation);
            el('feeds').value = Core.csv(initial.rows); invalidate(); el('restore-consent').checked = false;
            restoreSummary();
            status('Previous app configuration restored and verified. Historical backup and inventory files retained.');
        }
        el('restore').onclick = () => run('Restoring previous app settings…', async () => {
            if (!el('restore-consent').checked) throw new Error('Confirm restore before continuing.');
            await restoreSettings(el('backup-id').value.trim());
        });
        el('restore-current').onclick = () => run('Checking the current configuration backup…',async()=>{
            if (!el('restore-current-consent').checked) throw new Error('Confirm restore before continuing.');
            if (!initial || !Core.backupId(initial)) throw new Error('No current wizard backup. Use a known backup ID below.');
            await restoreSettings(Core.backupId(initial));
        });
        async function checkSaved() {
            el('check-results').replaceChildren();
            const saved = await client.snapshot();
            if (!await client.effectiveScopeMatches(saved)) throw new Error('Your user-owned macro or lookup differs from the shared app configuration. Setup cannot certify the dashboard scope. Ask the administrator to reconcile the override; it was not changed.');
            if (saved.install.is_configured !== '1') throw new Error('Setup is not saved as configured. Preview and save first.');
            if (saved.source.definition !== Core.source(saved.rows)) throw new Error('Current scope differs from the wizard inventory. Use Review readiness for this custom configuration; no settings changed.');
            const result = await client.check(saved.rows);
            table(el('check-results'),result.rows,['event_host','index','sourcetype','records','status']);
            const bounds=document.createElement('p');bounds.className='setup-result warning';
            bounds.textContent='Feed check: last 24 hours, up to 10,001 records. '+(result.sample_capped?'SAMPLE LIMIT REACHED — counts are sampled and absence is inconclusive. ':'Counts are from a bounded recent sample, not complete fleet coverage.');
            el('check-results').prepend(bounds);
            const content = await client.contentCheck(saved.rows);
            const item = content[0] || {}, count=Number(item.unique_sampled_events||0);
            const summary = document.createElement('div'); summary.className='setup-result warning';
            summary.textContent = count ? 'Content sample: '+count+' unique event(s). '+Number(item.category_rows_with_all_fields||0)+' of '+Number(item.category_rows||0)+' category rows have all configured fields. Field presence is not control acceptance.' : 'No normalized events in the last 15-minute content sample. Content could not be assessed; this is not a pass.';
            el('check-results').appendChild(summary);
            const disclosure=document.createElement('details'), caption=document.createElement('summary');caption.textContent='Technical content-check details';disclosure.appendChild(caption);
            const details = document.createElement('pre');
            details.textContent = 'CONTENT SAMPLE — last 15 minutes, up to 1,001 raw records; partial audit groups are possible. Not a validation receipt.\n' + JSON.stringify(content,null,2);
            disclosure.appendChild(details);el('check-results').appendChild(disclosure);
            const gaps = result.rows.filter(r=>!r.status.startsWith('Recent')).length;
            status('Setup checked under your current account. ' + gaps + ' feed(s) need investigation. ' + (result.sample_capped ? 'SAMPLE LIMIT REACHED; absence is inconclusive. ' : '') + 'Open Review readiness for event-content checks. This is not full event validation or analyst-role certification.');
        }
        el('check').onclick = () => run('Checking saved configuration and recent feed presence…',checkSaved);
        run('Loading your current settings; no indexed discovery search yet…', async () => {
            initial = await client.snapshot();
            el('feeds').value = Core.csv(initial.rows);
            restoreSummary();
            let indexMessage = '';
            try {
                const result = await client.api('GET','/services/data/indexes',{count:201});
                if ((result.entry||[]).length>200) indexMessage = 'Index list capped; enter exact names if needed. ';
                (result.entry||[]).slice(0,200).filter(e=>!e.name.startsWith('_')).forEach(e=>{ const o=document.createElement('option'); o.value=e.name; o.textContent=e.name; el('indexes').appendChild(o); });
                if (el('indexes').options.length===1) {el('indexes').options[0].selected=true;indexMessage+='Only one accessible non-internal index is suggested; confirm it before discovery. ';}
            } catch (_) { indexMessage = 'Index listing is unavailable to this account; enter approved exact index names. '; }
            status(indexMessage + 'Existing settings loaded. ' + (initial.writable ? 'Choose indexes to discover, or import your expected feeds.' : 'Read-only account: an authorized administrator must save configuration.'));
        });
    });
});
