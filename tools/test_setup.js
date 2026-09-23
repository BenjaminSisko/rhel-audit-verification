/* Node's built-in test runner; no dependencies or Splunk credentials. */
'use strict';
const test=require('node:test'), assert=require('node:assert/strict');
const Core=require('../package/TA_au2_linux/appserver/static/setup_core.js');
const row={event_host:'rhel01.example.invalid',index:'rhel_audit',sourcetype:'linux:audit',owner:'Linux operations',max_silence_seconds:'3600',enabled:'1'};
const id='a'.repeat(32);
test('CSV round trip including quotes and comma',()=>{
    const r={...row,owner:'Operations, "East"'};
    assert.deepEqual(Core.parseCSV(Core.csv([r])),[r]);
});
test('BOM and CRLF imports',()=>assert.deepEqual(Core.parseCSV('\uFEFF'+Core.csv([row]).replace(/\n/g,'\r\n')),[row]));
test('Reject malformed, empty, duplicate and oversized inventories',()=>{
    for(const value of ['',Core.columns.join(','),Core.csv([row,row]),'"unclosed',Core.csv([{...row,enabled:'0'}])]) assert.throws(()=>Core.parseCSV(value));
    assert.throws(()=>Core.feeds(Array.from({length:201},(_,i)=>({...row,event_host:'h'+i}))));
});
test('Reject SPL injection and wildcard identities',()=>{
    for(const v of ['*','a" | delete','a`macro`','a\nfoo','a\\b','(a)','a b','a?']) for(const key of ['event_host','index','sourcetype']) assert.throws(()=>Core.feeds([{...row,[key]:v}]));
    assert.throws(()=>Core.feeds([{...row,owner:'`macro`'}]));
});
test('Reject invalid thresholds and missing owners',()=>{
    for(const v of ['0','59','2592001','NaN','3e3','-1']) assert.throws(()=>Core.feeds([{...row,max_silence_seconds:v}]));
    assert.throws(()=>Core.feeds([{...row,owner:''}]));
});
test('Exact tuple scope does not cross-join hosts and indexes',()=>{
    assert.equal(Core.source([row]),'search ((index="rhel_audit" host="rhel01.example.invalid" sourcetype="linux:audit"))');
    assert.ok(!Core.source([row,{...row,event_host:'disabled',enabled:'0'}]).includes('disabled'));
});
test('Bounded discovery requires explicitly chosen exact indexes',()=>{
    for(const v of [[],['*'],['a','b','c','d','e','f']]) assert.throws(()=>Core.discovery(v));
    assert.match(Core.discovery(['rhel_audit']),/head 10001/);
});
test('CSV writes are unique app-only lookup files, not indexed events',()=>{
    const q=Core.inventoryQuery([row],'aulx_setup_'+id+'.csv');
    assert.match(q,/outputlookup createinapp=true override_if_empty=false/);
    assert.ok(!q.includes('| collect'));
    assert.throws(()=>Core.inventoryQuery([row],'existing.csv'));
});

function fake() {
    let snapshot={source:{definition:'search index=old',iseval:'0'},lookup:{filename:'original.csv'},install:{is_configured:'0'},rows:[row],writable:true};
    const initial=structuredClone(snapshot), records={}, files={}, calls=[];
    let failPath=null, failOnce=false, concurrent=false;
    const c=new Core.Client(async()=>{},'TA_au2_linux');
    c.snapshot=async()=>structuredClone(snapshot);
    c.record=async(k,v)=>{records[k]=structuredClone(v); calls.push('record:'+k);};
    c.search=async(q)=>{
        calls.push(q);
        if(q.includes('outputlookup')) { files['aulx_setup_'+id+'.csv']=[row]; if(concurrent) snapshot.source.definition='search index=another_admin'; return [row]; }
        return [row];
    };
    const mapping={'configs/conf-macros/aulx_source':'source','configs/conf-transforms/aulx_expected_sources':'lookup','configs/conf-app/install':'install'};
    c.entry=async path=>{
        if(path.startsWith('configs/conf-aulx_setup/backup_')) return {content:{snapshot:JSON.stringify(records['backup_'+id])}};
        return {content:{...snapshot[mapping[path]]}};
    };
    c.api=async(method,path,args)=>{
        calls.push(path);
        if(method==='POST') {
            snapshot[mapping[path]]={...args};
            if(path===failPath && !failOnce) {failOnce=true;throw Error('timeout after commit');}
        }
        if(snapshot.lookup.filename!=='original.csv') snapshot.rows=files[snapshot.lookup.filename]||[];
        else snapshot.rows=initial.rows;
        return {};
    };
    return {c,initial,records,calls,setFailure:p=>failPath=p,setConcurrent:()=>concurrent=true,mutate:()=>snapshot.source.definition='search index=intervening'};
}
test('Save backs up before writes and verifies unique inventory',async()=>{
    const f=fake();const result=await f.c.save(f.initial,[row],id);
    assert.ok(f.calls[0].startsWith('record:backup_'));assert.equal(result.current.install.is_configured,'1');assert.equal(result.current.lookup.filename,'aulx_setup_'+id+'.csv');
    assert.deepEqual(f.records['backup_'+id].before,f.initial);
});
test('Stale preview refuses every write',async()=>{const f=fake();f.mutate();await assert.rejects(f.c.save(f.initial,[row],id),/changed since preview/);assert.equal(f.calls.length,0);});
test('Change during inventory creation is not overwritten',async()=>{const f=fake();f.setConcurrent();await assert.rejects(f.c.save(f.initial,[row],id),/changed during save/);assert.equal((await f.c.snapshot()).source.definition,'search index=another_admin');});
test('Each uncertain configuration write is rolled back and read back',async()=>{
    for(const p of ['configs/conf-macros/aulx_source','configs/conf-transforms/aulx_expected_sources','configs/conf-app/install']) {
        const f=fake();f.setFailure(p);await assert.rejects(f.c.save(f.initial,[row],id),/retained\/restored/);assert.deepEqual(await f.c.snapshot(),f.initial);
    }
});
test('Read-only and parallel saves rejected',async()=>{
    const f=fake();await assert.rejects(f.c.save({...f.initial,writable:false},[row],id),/administrator/);
    f.c.active=true;await assert.rejects(f.c.save(f.initial,[row],id),/already running/);
});
test('Restore previous scope/inventory and refuse intervening changes',async()=>{
    const f=fake();await f.c.save(f.initial,[row],id);assert.deepEqual(await f.c.restore(id),f.initial);
    const g=fake();await g.c.save(g.initial,[row],id);g.mutate();await assert.rejects(g.c.restore(id),/changed after/);
});
test('Sample cap and silent expected host stay explicit',async()=>{
    const c=new Core.Client(()=>{},'TA_au2_linux');c.search=async()=>[{...row,records:'10001',last_seen:String(Date.now()/1000)}];
    const result=await c.check([row,{...row,event_host:'silent'}]);
    assert.equal(result.sample_capped,true);assert.match(result.rows[1].status,/No records/);assert.match(result.rows[0].status,/content validation still required/);
});
test('Search timeout/finalization cancels job and never returns pass',async()=>{
    const calls=[];const c=new Core.Client(async(method,path)=>{calls.push([method,path]);if(method==='POST')return {sid:'test.1'};return {};},'TA_au2_linux');
    c.entry=async()=>({content:{isDone:true,isFinalized:true}});
    await assert.rejects(c.search('| makeresults'),/finalized early/);assert.equal(calls.at(-1)[0],'DELETE');
});
test('API warnings fail closed',async()=>{
    const c=new Core.Client(async()=>({messages:[{type:'WARN',text:'truncated'}]}),'TA_au2_linux');
    await assert.rejects(c.api('GET','test'),/truncated/);
});
test('Uncertain request never claims final rollback success',async()=>{
    const f=fake();const api=f.c.api.bind(f.c);let fired=false;
    f.c.api=async(method,path,args)=>{const v=await api(method,path,args);if(!fired){fired=true;const e=Error('network timeout');e.uncertain=true;throw e;}return v;};
    await assert.rejects(f.c.save(f.initial,[row],id),/late write is possible/);
});
test('Effective user override is detected, not deleted',async()=>{
    const c=new Core.Client(()=>{},'TA_au2_linux');
    c.entry=async path=>path.includes('current-context')?{content:{username:'reviewer'}}:path.includes('conf-macros')?{content:{definition:'search index=private'}}:{content:{filename:'old.csv'}};
    assert.equal(await c.effectiveScopeMatches({source:{definition:'search index=shared'},lookup:{filename:'old.csv'}}),false);
});
test('Dictionary-shaped job warnings are rejected',async()=>{
    const c=new Core.Client(async(method)=>method==='POST'?{sid:'test.1'}:{},'TA_au2_linux');
    c.entry=async()=>({content:{isDone:'1',isFinalized:'0',resultCount:0,messages:{WARN:['truncated']}}});
    await assert.rejects(c.search('| makeresults'),/warnings/);
});
test('HTTP permission denial produces no setup success',async()=>{
    const c=new Core.Client(async()=>{throw Error('403 forbidden');},'TA_au2_linux');
    await assert.rejects(c.snapshot(),/403/);
});
