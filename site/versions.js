/* Aggregate firmware history. No device identities or credentials are used. */
(() => {
  'use strict';
  const el = id => document.getElementById(id);
  const fmt = n => new Intl.NumberFormat('en-US').format(n);
  const pct = n => `${n.toFixed(1)}%`;
  const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const readableDate = (value, full=false) => new Date(`${value}T00:00:00Z`).toLocaleDateString('en-GB', {day:'numeric',month:'short',...(full ? {year:'numeric'} : {}),timeZone:'UTC'});
  const groups = [
    {key:'legacy', label:'Legacy SMG09', color:'#9e4835'},
    {key:'v3', label:'3.x', color:'#bd8051'},
    {key:'early4', label:'4.0–4.2', color:'#c6b56f'},
    {key:'v431', label:'4.3.1', color:'#7e9c83'},
    {key:'v5', label:'5.x', color:'#355b49'},
    {key:'unknown', label:'Unknown', color:'#c8ccc4'}
  ];
  let dataset, measure='share';
  const population = () => el('exclude-honeypots').checked ? 'excludingHoneypots' : 'all';
  function grouped(sample) {
    const values=Object.fromEntries(groups.map(g=>[g.key,0]));
    for(const [version,count] of Object.entries(sample.versions)) {
      const key=version.startsWith('SMG')?'legacy':version.startsWith('3.')?'v3':version==='4.3.1'?'v431':version.startsWith('4.')?'early4':version.startsWith('5.')?'v5':'unknown';
      values[key]+=count;
    }
    return values;
  }
  function newerShare(sample) {
    const values=grouped(sample);
    return sample.total ? 100*(values.v431+values.v5)/sample.total : null;
  }
  function render() {
    if(!dataset?.history?.length) {
      el('firmware-status').textContent='No successful firmware observation yet. The daily collection will establish a baseline.';
      return;
    }
    const allRows=dataset.history;
    const latestPolicy=allRows.at(-1).populationPolicy || 'original-title-query';
    const comparableRows=allRows.filter(row=>(row.populationPolicy || 'original-title-query')===latestPolicy);
    const rows=allRows.slice(-30);
    const latestRow=allRows.at(-1), selected=population(), latest=latestRow[selected];
    const share=newerShare(latest);
    el('firmware-newer').textContent=share===null?'—':pct(share);
    el('firmware-total').textContent=fmt(latest.total);
    el('firmware-excluded').textContent=fmt(latestRow.honeypotServicesExcluded);
    const stale=Date.now()-Date.parse(latestRow.collectedAt)>48*60*60*1000;
    const state=dataset.status==='error'?' · latest collection failed; showing previous data':dataset.status==='awaiting_key'?' · credential unavailable':stale?' · refresh overdue':'';
    el('firmware-status').textContent=`Observed ${readableDate(latestRow.date,true)} UTC · ${el('exclude-honeypots').checked?'tagged honeypots excluded':'all matching services, including tagged honeypots'}${latestRow.manuallyExcludedIPs ? ' · two manually excluded IPs omitted' : ''}${state}`;
    el('firmware-legend').innerHTML=groups.map(g=>`<span><i style="background:${g.color}"></i>${g.label}</span>`).join('');
    const width=Math.max(300,el('firmware-chart').clientWidth), left=58, right=65, top=38, rowHeight=44;
    const height=top+rows.length*rowHeight+18, plot=width-left-right;
    const ceiling=measure==='share'?100:Math.max(1,...rows.map(row=>row[selected].total));
    const parts=[];
    for(let i=0;i<=4;i++) {
      const value=ceiling*i/4, x=left+plot*i/4;
      parts.push(`<path d="M${x} 24V${height-8}" stroke="#d7dbd0" stroke-dasharray="3 5"/><text x="${x}" y="14" text-anchor="middle">${measure==='share'?`${value}%`:fmt(Math.round(value))}</text>`);
    }
    rows.forEach((row,index)=>{
      const sample=row[selected], values=grouped(sample), y=top+index*rowHeight;
      parts.push(`<text x="${left-9}" y="${y+18}" text-anchor="end">${readableDate(row.date)}</text>`);
      let offset=0;
      groups.forEach(group=>{
        const value=values[group.key], units=measure==='share'?(sample.total?100*value/sample.total:0):value;
        const size=units/ceiling*plot;
        if(value>0) parts.push(`<rect x="${left+offset}" y="${y}" width="${size}" height="28" fill="${group.color}"><title>${readableDate(row.date,true)} · ${group.label}: ${fmt(value)} services (${pct(sample.total?100*value/sample.total:0)})</title></rect>`);
        offset+=size;
      });
      parts.push(`<text x="${left+plot+9}" y="${y+18}">${fmt(sample.total)}</text>`);
    });
    el('firmware-chart').innerHTML=`<svg viewBox="0 0 ${width} ${height}" role="img" aria-labelledby="firmware-svg-title firmware-svg-description"><title id="firmware-svg-title">Global inferred firmware mix by day</title><desc id="firmware-svg-description">${rows.length} daily observations shown as stacked bars. ${measure==='share'?'Bar segments show percentage shares.':'Bar segments show service counts on a shared scale.'} Latest total: ${fmt(latest.total)}. Full values are available in the table and downloadable history.</desc>${parts.join('')}</svg>`;
    if(comparableRows.length===1) {
      el('firmware-trend').textContent=latestRow.manuallyExcludedIPs ? 'New baseline after excluding two suspected emulation addresses on 6 November. Earlier rows retain the original population; no comparable trend is available yet.' : 'First baseline collected. A trend will appear after the next successful daily observation; no upgrade rate can be inferred yet.';
    } else {
      const firstRow=comparableRows.slice(-30)[0], first=firstRow[selected], firstShare=newerShare(first);
      if(firstShare===null || share===null) {
        el('firmware-trend').textContent='A zero-service observation has no defined version share. Compare service counts to see the population change.';
      } else {
        const difference=share-firstShare;
        el('firmware-trend').textContent=`Since ${readableDate(firstRow.date,true)}, the share inferred as 4.3.1 or 5.x changed by ${difference>=0?'+':''}${difference.toFixed(1)} percentage points; matching services changed from ${fmt(first.total)} to ${fmt(latest.total)}. ${allRows.length>30?'Showing the latest 30 observations. ':''}This is a change in the exposed population, not a measured device-upgrade rate.`;
      }
    }
    el('firmware-table-caption').textContent=`${readableDate(latestRow.date,true)} · ${el('exclude-honeypots').checked?'tagged honeypots excluded':'all matching services'}`;
    el('firmware-breakdown').innerHTML=Object.entries(latest.versions).filter(([,count])=>count>0).sort((a,b)=>b[1]-a[1]).map(([version,count])=>`<tr><td>${escape(version)}</td><td>${fmt(count)}</td><td>${latest.total?pct(100*count/latest.total):'—'}</td></tr>`).join('') || '<tr><td colspan="3">No matching services.</td></tr>';
  }
  document.querySelectorAll('[data-firmware-measure]').forEach(button=>button.addEventListener('click',()=>{
    measure=button.dataset.firmwareMeasure;
    document.querySelectorAll('[data-firmware-measure]').forEach(other=>other.setAttribute('aria-pressed',String(other===button)));
    render();
  }));
  el('exclude-honeypots').addEventListener('change',render);
  el('firmware-download').addEventListener('click',()=>{
    if(!dataset?.history?.length) return;
    const cells=[['date','population','inferred_version','services','population_total','population_policy']];
    for(const row of dataset.history) for(const scope of ['all','excludingHoneypots']) for(const [version,count] of Object.entries(row[scope].versions)) cells.push([row.date,scope,version,count,row[scope].total,row.populationPolicy || 'original-title-query']);
    const csv=cells.map(row=>row.map(value=>'"'+String(value).replace(/"/g,'""')+'"').join(',')).join('\r\n');
    const url=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8;'}));
    const link=document.createElement('a');link.href=url;link.download='storeview-firmware-history.csv';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  });
  new ResizeObserver(()=>{ if(dataset) render(); }).observe(el('firmware-chart'));
  fetch('data/versions.json',{cache:'no-cache'}).then(response=>{
    if(!response.ok) throw new Error('Unavailable');
    return response.json();
  }).then(data=>{dataset=data;render();}).catch(()=>{el('firmware-status').textContent='Firmware data could not be loaded. Please try again later.';});
})();
