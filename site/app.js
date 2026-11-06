'use strict';
const $ = id => document.getElementById(id);
const number = n => new Intl.NumberFormat('en-US').format(n);
const escapeHTML = value => String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const date = value => new Date(value.length === 10 ? `${value}T00:00:00Z` : value).toLocaleDateString('en-GB', {day:'numeric',month:'short',year:'numeric',timeZone:'UTC'});
const utcDay = value => Date.UTC(value.getUTCFullYear(), value.getUTCMonth(), value.getUTCDate());
const age = value => Math.floor((utcDay(new Date()) - utcDay(new Date(value))) / 86400000);
let rows = [], scope = 'worldwide';

function regionCount(row) { return scope === 'france' ? row.france : row.count; }
function renderChart() {
  const available = rows.filter(row => Number.isInteger(regionCount(row)));
  $('observations').innerHTML = available.map(row => `<tr><td>${date(row.date)}</td><td>${number(regionCount(row))}</td><td><a href="${escapeHTML(row.url)}">${escapeHTML(row.source)} ↗</a></td><td>${row.kind === 'daily' ? 'Daily collection' : 'Published snapshot'}</td></tr>`).join('');
  if (!available.length) { $('chart').textContent = 'No observations are available for this region yet.'; return; }
  const width=Math.max(300,$('chart').clientWidth), height=width<600?220:260, left=54, right=38, top=28, bottom=48;
  const times=available.map(row => Date.parse(row.date));
  let min=Math.min(...times), max=Math.max(...times);
  if (min === max) { min-=86400000; max+=86400000; }
  const ceiling=Math.max(100, Math.ceil(Math.max(...available.map(regionCount))*1.15/100)*100);
  const x=t => left+(t-min)/(max-min)*(width-left-right);
  const y=n => height-bottom-n/ceiling*(height-top-bottom);
  let parts=[];
  for(let i=0;i<=4;i++) {const v=Math.round(ceiling*i/4);parts.push(`<path d="M${left} ${y(v)}H${width-right}" stroke="#d7dbd0" stroke-dasharray="3 5"/><text x="${left-15}" y="${y(v)+4}" text-anchor="end">${number(v)}</text>`);}
  const labels=[...new Set([times[0],times[times.length-1]])];
  labels.forEach(t => parts.push(`<text x="${x(t)}" y="${height-13}" text-anchor="middle">${date(new Date(t).toISOString().slice(0,10))}</text>`));
  available.forEach((row,i) => {const v=regionCount(row);parts.push(`<circle cx="${x(times[i])}" cy="${y(v)}" r="5" fill="${row.kind==='daily'?'#396650':'#f5f3ec'}" stroke="${row.kind==='daily'?'#396650':'#b73825'}" stroke-width="2"><title>${escapeHTML(date(row.date))}: ${number(v)} services · ${escapeHTML(row.source)}</title></circle>`);});
  const latest=available[available.length-1];
  parts.push(`<text x="${x(times[times.length-1])}" y="${y(regionCount(latest))-14}" text-anchor="middle" style="fill:#273c33;font-weight:700">${number(regionCount(latest))}</text>`);
  $('chart').innerHTML=`<svg viewBox="0 0 ${width} ${height}" role="img" aria-labelledby="chart-title chart-desc"><title id="chart-title">Shodan services: ${scope === 'france' ? 'France' : 'worldwide'}</title><desc id="chart-desc">${available.length} dated observations. Latest: ${number(regionCount(latest))} services on ${date(latest.date)}. Full values and sources are in the table below. No interpolation between observations.</desc>${parts.join('')}</svg>`;
}

async function start() {
  try {
    const [status,incidents,shodan,published,hosts]=await Promise.all(['status','incidents','shodan','reported-counts','hosts'].map(async name => {
      try {
        const response=await fetch(`data/${name}.json`,{cache:'no-cache'});
        if(!response.ok) throw new Error('Data unavailable');
        return await response.json();
      } catch(error) {
        if(name==='hosts') return null;
        throw error;
      }
    }));
    $('answer').textContent=status.answer;
    $('summary').textContent=status.summary;
    $('status-reason').textContent=status.reason;
    $('review-date').textContent=`News reviewed ${date(status.reviewedAt)}${age(status.reviewedAt)>2?' · Review overdue':''}`;
    const major=incidents.filter(item => item.major && Date.parse(item.date)<=Date.now()).sort((a,b)=>a.date.localeCompare(b.date)).at(-1);
    const updateDays=()=>{ $('days').textContent=major ? String(Math.max(0,age(major.date))).padStart(2,'0') : '—'; };
    updateDays(); setInterval(updateDays,60000);
    $('last-attack').textContent=major ? `Latest wave: ${date(major.date)}` : 'No qualifying incident recorded';
    const latest=shodan.history.at(-1), baseline=hosts?.history?.at(-1);
    const stale=baseline && age(baseline.collectedAt)>2;
    $('count-label').textContent='Baseline · distinct IP addresses';
    $('count').textContent=baseline ? number(baseline.excludingTaggedServices.uniqueIPs) : '—';
    $('count-date').textContent=baseline ? `Collected ${date(baseline.collectedAt)} UTC · ${stale?'stale measurement':'daily snapshot'}` : 'Filtered baseline unavailable';
    $('honeypot-note').textContent=baseline ? `* ${number(baseline.all.uniqueIPs)} IPs before honeypot filtering; ${number(baseline.all.services)} service results, including ${number(baseline.taggedServicesExcluded)} tagged as honeypots.${baseline.manuallyExcludedIPs ? ` Both totals omit ${baseline.manuallyExcludedIPs} manually excluded addresses.` : ''}` : latest ? `* Last unfiltered total: ${number(latest.count)}. The honeypot breakdown is unavailable.` : '* Total including tagged honeypots unavailable.';
    $('collection-state').textContent=!baseline ? 'Baseline unavailable' : hosts.status==='error' ? 'Collection failed' : hosts.status==='awaiting_key' ? 'Daily count pending' : stale ? 'Data refresh overdue' : 'Daily count connected';
    $('collection-detail').textContent=`Baseline last attempt: ${hosts?.lastAttemptAt ? date(hosts.lastAttemptAt) : 'unavailable'}. Baseline last success: ${hosts?.lastSuccessAt ? date(hosts.lastSuccessAt) : 'unavailable'}. Unfiltered exposure last success: ${shodan.lastSuccessAt ? date(shodan.lastSuccessAt) : 'not yet run'}.`;
    rows=[...published.map(row=>({...row,kind:'published'})),...shodan.history.map(row=>({...row,france:row.countries.FR ?? null,kind:'daily',source:'Shodan count API',url:'https://developer.shodan.io/api#shodan-host-count'}))].sort((a,b)=>a.date.localeCompare(b.date));
    renderChart();
    $('incidents').innerHTML=incidents.map(item=>`<article class="incident"><div class="incident-date">${escapeHTML(item.dateLabel)}<small>${escapeHTML(item.location)}</small></div><div class="incident-body"><span class="badge">${escapeHTML(item.classification)}</span><h3>${escapeHTML(item.title)}</h3><p>${escapeHTML(item.summary)}</p><div class="sources">${item.sources.map(source=>`<a href="${escapeHTML(source.url)}">${escapeHTML(source.name)} ↗</a>`).join('')}</div></div></article>`).join('');
  } catch(error) { $('load-error').hidden=false; $('count-date').textContent='Data unavailable'; }
}
document.querySelectorAll('[data-scope]').forEach(button=>button.addEventListener('click',()=>{
  scope=button.dataset.scope;
  document.querySelectorAll('[data-scope]').forEach(item=>item.setAttribute('aria-pressed',String(item===button)));
  renderChart();
}));
$('download').addEventListener('click',()=>{
  const csvCell=value=>'"'+String(value ?? '').replace(/"/g,'""')+'"';
  const csv=[['date','services','scope','type','source','source_url'],...rows.map(row=>[row.date,regionCount(row),scope,row.kind,row.source,row.url])].map(row=>row.map(csvCell).join(',')).join('\r\n');
  const url=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8;'}));
  const a=document.createElement('a');a.href=url;a.download=`fridge-exposure-${scope}.csv`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
new ResizeObserver(() => { if(rows.length) renderChart(); }).observe($('chart'));
start();
