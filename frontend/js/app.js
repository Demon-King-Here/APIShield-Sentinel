'use strict';
const $ = (s, root=document) => root.querySelector(s);
const $$ = (s, root=document) => [...root.querySelectorAll(s)];
const esc = v => String(v ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const number = v => Number(v || 0).toLocaleString(undefined,{maximumFractionDigits:2});
const time = v => v ? new Date(v).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'}) : 'Never';
const date = v => v ? new Date(v).toLocaleString() : 'Never';
const titles = {overview:['Overview','A clear view of your APIs, traffic, and security posture.'],discovery:['API Discovery','Discover listening sockets and inspect the evidence behind each service.'],inventory:['API Inventory','Manage gateway routes and verify their security boundaries.'],traffic:['Live Traffic','Inspect actual HTTP requests observed at the gateway.'],policies:['Security Policies','Define the controls applied to each configured gateway route.'],events:['Security Events','Trace gateway decisions, discovery findings, and verification results.'],audit:['Audit Logs','A persistent record of administrative actions and configuration changes.'],settings:['Settings','Inspect runtime configuration and manage retained monitoring history.']};
const state = {authenticated:false,csrf:'',setup:false,page:'overview',services:[],listeners:[],metrics:{},charts:{},edit:null,stream:null,refreshing:false,streamGeneration:0,lastInteraction:Date.now()};

function toast(message){$('#toast').textContent=message;$('#toast').hidden=false;clearTimeout(state.toast);state.toast=setTimeout(()=>$('#toast').hidden=true,5000);}
function failure(error){$('#error-banner').textContent=error.message || String(error);$('#error-banner').hidden=false;}
function badge(value){const str=String(value ?? 'Unknown');const cls=/failed|error|unavailable|^5\d\d/.test(str.toLowerCase())?'error':/exposed|review|blocked|429|warning/.test(str.toLowerCase())?'warning':/success|^2\d\d|completed/.test(str.toLowerCase())?'success':/unknown|disabled|unverified|not evaluated/.test(str.toLowerCase())?'muted':'';return `<span class="badge ${cls}">${esc(str)}</span>`;}
function empty(columns,message){return `<tr><td colspan="${columns}" class="empty-state">${esc(message)}</td></tr>`;}
async function api(path, options={}){
  const headers = {...options.headers};
  if(options.method && !['GET','HEAD'].includes(options.method)){headers['X-APIShield-Action']='admin';if(state.csrf)headers['X-CSRF-Token']=state.csrf;if(options.body)headers['Content-Type']='application/json';}
  const response=await fetch(`/api/${path}`,{...options,headers,credentials:'same-origin',cache:'no-store'});
  if(!response.ok){let data;try{data=await response.json();}catch{data={};}if(response.status===401&&state.authenticated&&!['auth/login','auth/password'].includes(path))lock();throw new Error(data.error?.message || `Request failed (${response.status})`);}
  return options.raw ? response : response.status===204?null:response.json();
}
const post = (path,body) => api(path,{method:'POST',...(body?{body:JSON.stringify(body)}:{})});
const metric = (label,value,unit='',foot='',symbol='◈',cls='') => `<article class="metric ${cls}"><div class="metric-label">${esc(label)}<span class="metric-symbol">${symbol}</span></div><div class="metric-value">${number(value)}<small>${esc(unit)}</small></div><div class="metric-foot">${esc(foot)}</div></article>`;

function chart(id,type,data,options={}){
  if(!window.Chart)return;
  if(state.charts[id]){const c=state.charts[id];c.data=data;c.update('none');return;}
  const base={responsive:true,maintainAspectRatio:false,animation:false,plugins:{legend:{display:false},tooltip:{backgroundColor:'#1b2a3b',titleColor:'#dce7f4',bodyColor:'#b9c9dd',borderColor:'#35495f',borderWidth:1}},scales:{x:{grid:{display:false},ticks:{color:'#71859f',font:{size:9},maxTicksLimit:6},border:{display:false}},y:{beginAtZero:true,grid:{color:'#25314270'},ticks:{color:'#71859f',font:{size:9},maxTicksLimit:5,precision:0},border:{display:false}}}};
  if(type==='doughnut')delete base.scales;
  state.charts[id]=new Chart($(`#${id}`),{type,data,options:{...base,...options}});
}
function renderMetrics(m,t){
  $('#primary-metrics').innerHTML=metric('Listening ports',m.listening_ports,'','Observed in last scan','⌕')+metric('Potential API services',m.potential_apis,'','Evidence from configured routes','▤')+metric('Confirmed exposed',m.confirmed_exposed,'','No external probe performed','◇')+metric('Gateway-managed',m.gateway_managed,'','Enabled routes · isolation separate','⇄','accent');
  $('#secondary-metrics').innerHTML=metric('Requests per second',m.rps,'req/s','Rolling 10-second average','↗')+metric('Total requests processed',m.total_requests,'','Retained 30-day aggregate','⇄')+metric('Blocked requests',m.blocked,'','Gateway policy rejections','⊘','warn')+metric('Average response time',m.average_latency,'ms','End-to-end gateway duration','◷')+metric('Services requiring review',m.needs_review,'','Last observed listener bindings','⚑','warn')+metric('HTTP error rate',m.error_rate,'%','HTTP 4xx + 5xx responses','≋')+metric('System CPU',m.cpu,'%','Machine-wide measured utilization','▥')+metric('System memory',m.memory,'%','Machine-wide measured utilization','▤');
  $('#traffic-metrics').innerHTML=metric('Successful requests',m.successful,'','Retained HTTP 2xx / 3xx')+metric('Client errors',m.client_errors,'','Retained HTTP 4xx','⊘','warn')+metric('Upstream / server errors',m.upstream_errors,'','Retained HTTP 5xx','⚑')+metric('Latency p95',m.p95,'ms',`p50 ${number(m.p50)} ms · p99 ${number(m.p99)} ms`);
  $('#last-scan').textContent=m.last_scan?`Last scan ${time(m.last_scan)}`:'No scan performed';
  $('#metrics-scope').textContent=m.scope || '';
  $('#latency-p95').textContent=`p95 ${number(m.p95)} ms`;
  const labels=t.series.map(v=>time(v.bucket+':00Z').slice(0,5));
  const line=(name,values,color,fill=false)=>({label:name,data:values,borderColor:color,backgroundColor:fill?'#53c9ee10':color,borderWidth:2,fill,tension:.35,pointRadius:values.length===1?3:0,pointHoverRadius:4});
  chart('traffic-chart','line',{labels,datasets:[line('Total requests',t.series.map(v=>v.total),'#53c9ee',true),line('Blocked',t.series.map(v=>v.blocked),'#e8b76a')]});
  $('#traffic-empty').hidden=t.series.length>0;
  const blocked=Number(m.blocked||0),allowed=Number(m.total_requests||0)-blocked;
  chart('decisions-chart','doughnut',{labels:['Allowed','Blocked'],datasets:[{data:m.total_requests?[allowed,blocked]:[0,0],backgroundColor:['#53c9ee','#e8b76a'],borderWidth:0,hoverOffset:3}]},{cutout:'83%'});
  $('#decision-total').textContent=number(m.total_requests);$('#allowed-count').textContent=number(allowed);$('#blocked-count').textContent=number(blocked);
  chart('api-chart','bar',{labels:t.apis.map(v=>v.api_name),datasets:[{label:'Requests',data:t.apis.map(v=>v.total),backgroundColor:'#508ec9',borderRadius:3,maxBarThickness:28}]},{indexAxis:'y'});
  chart('status-chart','bar',{labels:t.statuses.map(v=>String(v.status)),datasets:[{label:'Responses',data:t.statuses.map(v=>v.total),backgroundColor:t.statuses.map(v=>v.status>=500?'#f28690':v.status>=400?'#e8b76a':'#53c9ee'),borderRadius:3,maxBarThickness:38}]});
  chart('latency-chart','line',{labels,datasets:[line('Average ms',t.series.map(v=>v.latency),'#839df0',true)]});
}
function miniEvents(rows){$('#recent-events').innerHTML=rows.length?rows.slice(0,4).map(r=>`<div class="mini-event"><span class="dot ${r.severity==='error'?'red':r.severity==='warning'?'amber':'cyan'}"></span><div>${esc(r.type.replaceAll('_',' '))}<p>${esc(r.detail)}</p></div><time>${time(r.timestamp)}</time></div>`).join(''):'<div class="empty-state">No security events yet.<br>Send a request through the gateway to begin.</div>';}

function filterQuery(page){
  const p=new URLSearchParams();const value=id=>$(`#${id}`)?.value||'';
  const set=(key,v)=>{if(v)p.set(key,v);};
  if(page==='discovery'){set('q',value('discovery-search'));set('port',value('discovery-port'));set('process',value('discovery-process'));set('classification',value('discovery-type'));}
  if(page==='traffic'||page==='events'){
    set('q',value(`${page}-search`));set('service_id',value(`${page}-api`));
    for(const range of ['since','until']){const v=value(`${page}-${range}`);if(v)set(range,new Date(v).toISOString());}
    if(page==='traffic'){set('status',value('traffic-status'));set('decision',value('traffic-decision'));}
    else{set('type',value('events-type'));set('severity',value('events-severity'));}
  }
  return p;
}
function serviceOptions(){for(const id of ['traffic-api','events-api']){const selected=$(`#${id}`).value;$(`#${id}`).innerHTML='<option value="">All APIs</option>'+state.services.map(s=>`<option value="${esc(s.id)}">${esc(s.name)}</option>`).join('');$(`#${id}`).value=selected;}}
function renderDiscovery(data){
  state.listeners=data.listeners;
  $('#scan-detail').textContent=data.scan?`${data.scan.source} · ${date(data.scan.timestamp)} · ${data.listeners.length} matching listeners. ${data.scan.limitations.join(' ')}`:'No scan yet. Select Scan now to enumerate local listening ports.';
  $('#discovery-rows').innerHTML=data.listeners.length?data.listeners.map((r,i)=>`<tr><td><strong>${esc(r.port)}</strong><small>${esc(r.local_address)}</small></td><td>${esc(r.process)}<small>PID ${esc(r.pid)}</small></td><td>${badge(r.classification)}</td><td>${badge(r.reachability)}<small>${esc(r.binding_scope)} binding</small></td><td>${badge(r.gateway_status)}</td><td>${badge(r.security_status)}</td><td><button class="button" data-listener="${i}">Details ↗</button></td></tr>`).join(''):empty(7,'No listeners match. Run a scan or adjust the filters.');
}
function renderInventory(){
  const q=$('#inventory-search').value.toLowerCase();const services=state.services.filter(s=>JSON.stringify(s).toLowerCase().includes(q));
  $('#inventory-cards').innerHTML=services.length?services.map(s=>`<article class="panel service-card"><div class="card-heading"><span class="service-icon">▤</span><div class="card-name"><h2>${esc(s.name)}</h2><p>${esc(s.backend_url)}</p></div>${badge(s.enabled?s.security_state:'Disabled')}</div><dl><dt>Gateway path</dt><dd><code>${esc(s.gateway_path)}/*</code> ${s.strip_prefix?'→ strip prefix':'→ preserve path'}</dd><dt>Backend port</dt><dd>${esc(s.backend_port)}</dd><dt>Process / binding</dt><dd>${s.processes.length?s.processes.map(p=>esc(`${p.process} (${p.pid}) · ${p.local_address}`)).join('<br>'):'Unknown · run discovery'}</dd><dt>Health / verified</dt><dd>${s.verification?(s.verification.healthy?'Health passed':'Health failed')+' · '+date(s.verification.timestamp):'Not checked'}</dd><dt>Last observed</dt><dd>${date(s.last_observed)}</dd><dt>Observed requests</dt><dd>${number(s.total)} · ${number(s.rps)} req/s</dd><dt>Rate policy</dt><dd>${s.policy.limit} requests / ${s.policy.window}s / client</dd><dt>Authentication</dt><dd>${s.policy.client_key_env?'Key required · '+esc(s.policy.client_key_env):'Optional client authentication disabled'}</dd></dl><p class="service-explanation">${esc(s.verification?.explanation || (s.enabled?'Route enabled; forwarding and direct-access restrictions are unverified. Gateway policy applies only to requests through this route.':'Gateway route disabled. Backend process and binding remain unchanged.'))}</p><div class="card-actions"><button class="button" data-service-action="verify" data-id="${esc(s.id)}">Verify</button><button class="button" data-service-action="edit" data-id="${esc(s.id)}">Edit</button><button class="button" data-service-action="toggle" data-id="${esc(s.id)}">${s.enabled?'Disable':'Enable'}</button><button class="button" data-service-action="traffic" data-id="${esc(s.id)}">Traffic</button><button class="button remove" data-service-action="remove" data-id="${esc(s.id)}">Remove</button></div></article>`).join(''):'<div class="panel empty-state">No matching APIs. Add an API route to get started.</div>';
}
function renderPolicies(){
  $('#policy-cards').innerHTML=state.services.map(s=>`<article class="panel service-card"><div class="card-heading"><div><h2>${esc(s.name)}</h2><p>Per-client, per-route policy</p></div>${badge(s.enabled?'Enabled':'Disabled')}</div><div class="policy-list"><span class="chip">${s.policy.limit} requests / ${s.policy.window}s</span><span class="chip">${number(s.policy.max_body)} byte body limit</span><span class="chip">${s.timeout}s timeout</span></div><p class="policy-methods">${esc(s.policy.methods.join(' · '))}</p><dl><dt>Allowed paths</dt><dd>${esc(s.policy.allowed_paths.join(', '))}</dd><dt>Client authentication</dt><dd>${esc(s.policy.client_key_env || 'Disabled')}</dd><dt>Upstream bearer</dt><dd>${esc(s.policy.upstream_token_env || 'Not configured')}</dd></dl><p class="service-explanation">Source IP comes from the actual socket. Forwarding headers are discarded. Policy edits reset this route's rate window and invalidate previous verification.</p><button class="button" data-service-action="policy" data-id="${esc(s.id)}">Edit policy</button></article>`).join('')||'<div class="panel empty-state">Add an API to configure a policy.</div>';
}
function renderTraffic(rows){$('#traffic-rows').innerHTML=rows.length?rows.map(r=>`<tr><td>${time(r.timestamp)}<small>${new Date(r.timestamp).toLocaleDateString()}</small></td><td>${esc(r.api_name)}<small><code>${esc(r.path)}</code></small></td><td>${esc(r.method)}</td><td>${badge(r.status)}</td><td>${number(r.duration)} ms</td><td>${number(r.size)} B</td><td>${r.upstream_status?badge(r.upstream_status):'—'}</td><td>${badge(r.decision)}<small>${esc(r.error||r.rate_decision)}</small></td></tr>`).join(''):empty(8,'No observed gateway requests match these filters.');}
function renderEvents(rows){$('#events-timeline').innerHTML=rows.length?rows.map(r=>`<div class="timeline-event"><span class="event-icon ${esc(r.severity)}">${r.severity==='info'?'◇':'!'}</span><div><h3>${esc(r.type.replaceAll('_',' '))} ${badge(r.severity)}</h3><small>${esc(r.api_name||'System')}</small><p>${esc(r.detail)}</p></div><time>${date(r.timestamp)}</time></div>`).join(''):'<div class="empty-state">No matching events. Gateway activity and administrative actions will appear here.</div>';}
function renderAudit(rows){$('#audit-rows').innerHTML=rows.length?rows.map(r=>`<tr><td>${date(r.timestamp)}</td><td>${esc(r.action.replaceAll('_',' '))}</td><td>${esc(r.detail)}</td></tr>`).join(''):empty(3,'No administrative actions recorded.');}
async function refresh(full=false){
  if(!state.authenticated||state.refreshing)return;state.refreshing=true;
  try{
    const [m,t,h] = await Promise.all([api('metrics/overview'),api('metrics/traffic'),api('health')]);
    state.metrics=m;renderMetrics(m,t);
    const gatewayLabel=h.gateway?'Gateway online':h.gateway_state==='waiting_for_interface'?'Waiting for adapter':'Gateway unavailable';
    $('#system-label').textContent=gatewayLabel;$('#system-label').title=h.gateway_url||'Open Settings to inspect the selected network adapter';$('#system-dot').className='dot '+(h.gateway?'cyan':'red');
    $('#sidebar-gateway').textContent=h.gateway?`Gateway active · :${h.gateway_port}`:gatewayLabel;$('#sidebar-gateway-dot').className='dot '+(h.gateway?'cyan':'red');
    if(full || ['inventory','policies','discovery'].includes(state.page)){state.services=await api('services');serviceOptions();$('#route-count').textContent=state.services.length;}
    switch(state.page){
      case 'overview':miniEvents(await api('events?limit=4'));break;
      case 'discovery':renderDiscovery(await api('discovery/ports?'+filterQuery('discovery')));break;
      case 'inventory':renderInventory();break;
      case 'policies':renderPolicies();break;
      case 'traffic':renderTraffic(await api('traffic?'+filterQuery('traffic')));break;
      case 'events':renderEvents(await api('events?'+filterQuery('events')));break;
      case 'audit':renderAudit(await api('audit'));break;
      case 'settings':{const storage=await api('database');$('#database-details').innerHTML=`<p class="muted">${esc(storage.path)} · schema ${storage.schema_version} · ${number(storage.size_bytes/1024)} KiB including journal</p><dl class="detail-grid">${Object.entries(storage.tables).map(([name,count])=>`<dt>${esc(name.replaceAll('_',' '))}</dt><dd>${number(count)} records</dd>`).join('')}</dl><p class="footnote">History limit: ${number(storage.retention.history_rows)} rows per history table; ${storage.retention.discovery_scans} scans; ${storage.retention.aggregate_days} days of aggregates. System samples every ${storage.retention.system_interval_seconds} seconds.</p>`;const config=await api('settings');$('#runtime-settings').innerHTML=Object.entries(config).map(([k,v])=>`<dt>${esc(k.replaceAll('_',' '))}</dt><dd>${k==='gateway_url'&&v?`<a href="${esc(v)}/_sentinel/health" target="_blank" rel="noreferrer">${esc(v)}</a>`:esc(Array.isArray(v)?v.join(', '):v===null?'Waiting for selected adapter':String(v))}</dd>`).join('');break;}
    }
    $('#error-banner').hidden=true;
  }catch(e){failure(e);}finally{state.refreshing=false;}
}
function navigate(){const key=location.hash.slice(1);state.page=titles[key]?key:'overview';$$('.page').forEach(el=>el.hidden=el.id!==`page-${state.page}`);$$('nav a[data-page]').forEach(a=>{const active=a.dataset.page===state.page;a.classList.toggle('active',active);if(active)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');});$('#page-title').textContent=titles[state.page][0];$('#breadcrumb-page').textContent=titles[state.page][0];$('#page-subtitle').textContent=titles[state.page][1];document.title=`APIShield Sentinel · ${titles[state.page][0]}`;window.scrollTo(0,0);refresh(true);}

function formInput(label,name,value,type='text',extra=''){return `<label>${esc(label)}<input name="${name}" value="${esc(value)}" type="${type}" ${extra}></label>`;}
function openEditor(service=null,policyOnly=false){
  state.edit={service,policyOnly};const p=service?.policy||{limit:60,window:60,max_body:1048576,methods:['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'],allowed_paths:['/'],client_key_env:'',upstream_token_env:''};
  $('#editor-title').textContent=policyOnly?`Policy · ${service.name}`:service?'Edit API route':'Add an API';
  const fields=policyOnly?'':formInput('API name','name',service?.name||'','text','required maxlength="80"')+formInput('Backend origin (allowlisted literal IP + port)','backend_url',service?.backend_url||'http://127.0.0.1:5001','url','required')+formInput('Gateway route prefix','gateway_path',service?.gateway_path||'/example','text','required pattern="/[a-zA-Z0-9_-]{1,48}"')+`<div class="form-columns">${formInput('Health endpoint','health_path',service?.health_path||'/health','text','required')}${formInput('Verification backend path','verification_path',service?.verification_path||'/health','text','required')}</div>`+formInput('Upstream timeout (seconds)','timeout',service?.timeout||10,'number','min="0.1" max="30" step="0.1" required')+`<label class="checkbox-label"><input name="enabled" type="checkbox" ${!service||service.enabled?'checked':''}>Enable this gateway route</label><label class="checkbox-label"><input name="strip_prefix" type="checkbox" ${!service||service.strip_prefix?'checked':''}>Strip gateway prefix before forwarding</label>`;
  $('#editor-fields').innerHTML=fields+`<h2>Gateway policy</h2><div class="form-columns">${formInput('Requests per client','limit',p.limit,'number','min="1" max="10000" required')}${formInput('Window (seconds)','window',p.window,'number','min="1" max="3600" required')}</div>`+formInput('Maximum request body (bytes)','max_body',p.max_body,'number','min="0" max="4194304" required')+formInput('Allowed HTTP methods (comma-separated)','methods',p.methods.join(', '),'text','required')+formInput('Allowed gateway path prefixes (comma-separated)','allowed_paths',p.allowed_paths.join(', '),'text','required')+formInput('Client key environment variable (optional)','client_key_env',p.client_key_env)+formInput('Upstream bearer environment variable (optional)','upstream_token_env',p.upstream_token_env)+'<p class="footnote">Enter environment variable names, never secret values. Missing credentials cause requests to fail closed.</p>';
  $('#editor-error').textContent='';$('#editor').showModal();
}
async function saveEditor(event){
  event.preventDefault();const form=event.currentTarget;const values=Object.fromEntries(new FormData(form));const split=v=>v.split(',').map(s=>s.trim()).filter(Boolean);
  const policy={limit:Number(values.limit),window:Number(values.window),max_body:Number(values.max_body),methods:split(values.methods),allowed_paths:split(values.allowed_paths),client_key_env:values.client_key_env.trim(),upstream_token_env:values.upstream_token_env.trim()};
  const {service,policyOnly}=state.edit;const button=$('button[type=submit]',form);button.disabled=true;
  try{
    if(policyOnly)await api(`services/${service.id}/policy`,{method:'PUT',body:JSON.stringify(policy)});
    else{const body={name:values.name,backend_url:values.backend_url,gateway_path:values.gateway_path,health_path:values.health_path,verification_path:values.verification_path,timeout:Number(values.timeout),enabled:form.elements.enabled.checked,strip_prefix:form.elements.strip_prefix.checked,policy};await api(service?`services/${service.id}`:'services',{method:service?'PUT':'POST',body:JSON.stringify(body)});}
    $('#editor').close();toast('Configuration saved. Previous verification has been invalidated.');await refresh(true);
  }catch(e){$('#editor-error').textContent=e.message;}finally{button.disabled=false;}
}
function details(title,html){$('#detail-title').textContent=title;$('#detail-body').innerHTML=html;$('#detail').showModal();}
function configOnly(service){const {id,verification,backend_port,processes,total,last_observed,forwarded_observed,rps,security_state,...config}=service;return config;}
async function serviceAction(button){
  const s=state.services.find(v=>v.id===button.dataset.id);if(!s)return;const action=button.dataset.serviceAction;
  if(action==='edit'||action==='policy'){openEditor(s,action==='policy');return;}
  if(action==='traffic'){$('#traffic-api').value=s.id;location.hash='traffic';return;}
  if(action==='remove'&&!confirm(`Remove ${s.name} from the gateway? The backend process will continue running.`))return;
  button.disabled=true;
  try{
    if(action==='remove'){await api('services/'+s.id,{method:'DELETE'});toast('Gateway route removed. Backend process unchanged.');}
    if(action==='toggle'){const config=configOnly(s);config.enabled=!s.enabled;await api('services/'+s.id,{method:'PUT',body:JSON.stringify(config)});toast(config.enabled?'Gateway route enabled.':'Gateway route disabled.');}
    if(action==='verify'){
      toast('Checking backend health, gateway forwarding, and listener binding…');const report=await post(`services/${s.id}/verify`);
      details(`Verification · ${s.name}`,`${badge(report.state)}<p class="verification-text">${esc(report.explanation)}</p>${report.checks.map(c=>`<div class="check-row">${badge(c.passed===null?'Unknown':c.passed?'Passed':'Failed')}<strong>${esc(c.check)}</strong><p>${esc(c.detail)}</p></div>`).join('')}<p class="footnote">Checked ${date(report.timestamp)}. Results describe this observation, not future changes.</p>`);
    }
    await refresh(true);
  }catch(e){failure(e);}finally{button.disabled=false;}
}
async function scanNow(){const b=$('#scan-global');b.disabled=true;b.textContent='Scanning…';try{const result=await post('discovery/scan');toast(result.success?`Observed ${result.listeners.length} listening sockets.`:result.limitations.join(' '));await refresh(true);}catch(e){failure(e);}finally{b.disabled=false;b.innerHTML='<span>⌕</span> Scan now';}}
function downloadBlob(blob,name){const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}

async function stream(){
  const generation=++state.streamGeneration;
  while(state.authenticated&&generation===state.streamGeneration){
    try{
      state.stream=new AbortController();const response=await api('stream',{raw:true,signal:state.stream.signal});
      $('#stream-status').innerHTML='<span class="dot cyan"></span> Live stream connected';
      const reader=response.body.getReader();const decoder=new TextDecoder();let buffer='';
      while(true){const {value,done}=await reader.read();if(done)break;buffer+=decoder.decode(value,{stream:true});let i;while((i=buffer.indexOf('\n\n'))>=0){const packet=buffer.slice(0,i);buffer=buffer.slice(i+2);if(packet.includes('event: error'))throw new Error('Stream capacity reached');scheduleRefresh();}}
    }catch(e){$('#stream-status').innerHTML='<span class="dot amber"></span> Reconnecting live stream';}
    await new Promise(resolve=>setTimeout(resolve,3000));
  }
}
let refreshTimer;
function scheduleRefresh(){if(refreshTimer)return;refreshTimer=setTimeout(()=>{refreshTimer=null;refresh();},1500);}
async function initialize(){
  try{const session=await api('session');state.setup=session.setup_required;if(!session.authenticated){lock();return;}state.authenticated=true;state.lastInteraction=Date.now();state.csrf=session.csrf_token;document.body.classList.remove('auth-pending');if($('#login').open)$('#login').close();$('#login-form').reset();$('#error-banner').hidden=true;navigate();stream();}
  catch(e){lock();$('#login-error').textContent=e.message;}
}
function lock(){state.authenticated=false;state.csrf='';state.streamGeneration++;if(state.stream)state.stream.abort();state.services=[];state.listeners=[];state.metrics={};document.body.classList.add('auth-pending');$$('dialog[open]').forEach(el=>{if(el.id!=='login')el.close();});$('#setup-fields').hidden=!state.setup;$('#setup-code').required=state.setup;$('#confirm-password-label').hidden=!state.setup;$('#confirm-password').required=state.setup;$('#login-password').minLength=state.setup?15:1;$('#login-password').autocomplete=state.setup?'new-password':'current-password';$('#login-title').textContent=state.setup?'Create your administrator':'Administrator sign in';$('#login-description').textContent=state.setup?'Choose a username and a password or passphrase of at least 15 characters.':'Sign in to manage your APIs and view security data.';$('#login-submit').textContent=state.setup?'Create administrator':'Sign in';if(!$('#login').open)$('#login').showModal();}
$('#login').addEventListener('cancel',event=>event.preventDefault());

document.addEventListener('click',async event=>{
  const b=event.target.closest('button');if(!b)return;
  try{
    if(b.dataset.close){$(`#${b.dataset.close}`).close();return;}
    if(b.dataset.serviceAction){await serviceAction(b);return;}
    if(b.dataset.listener!==undefined){const r=state.listeners[Number(b.dataset.listener)];details(`Listener · port ${r.port}`,`<p class="verification-text">${esc(r.explanation)}</p><dl class="detail-grid">${Object.entries(r).map(([k,v])=>`<dt>${esc(k.replaceAll('_',' '))}</dt><dd>${esc(Array.isArray(v)?v.join(', ')||'Unavailable':v??'Unavailable')}</dd>`).join('')}</dl>`);return;}
    if(b.dataset.export){const route=b.dataset.export;const page=route==='discovery/ports'?'discovery':route;const query=filterQuery(page);query.set('format',b.dataset.format);const r=await api(`${route}?${query}`,{raw:true});downloadBlob(await r.blob(),`sentinel-${page}.${b.dataset.format}`);return;}
    switch(b.id){
      case 'refresh':case 'discovery-refresh':await refresh(true);break;
      case 'scan-global':await scanNow();break;
      case 'add-service':openEditor();break;
      case 'notifications':location.hash='events';break;
      case 'profile':location.hash='settings';break;
      case 'logout':await post('auth/logout');lock();$('#login-form').reset();$('#login-error').textContent='You have signed out.';break;
      case 'backup-database':{b.disabled=true;try{const response=await api('database/backup',{method:'POST',raw:true});downloadBlob(await response.blob(),'apishield-sentinel-backup.db');toast('Consistent SQLite backup downloaded.');}finally{b.disabled=false;}break;}
      case 'clear-history':if(confirm('Clear recorded traffic and monitoring history? API configurations, current discovery/verification, rate windows and audit history are preserved.')){await post('history/clear');toast('History cleared. Configurations and audit log preserved.');await refresh(true);}break;
    }
  }catch(e){failure(e);}
});
$('#editor-form').addEventListener('submit',saveEditor);
$('#login-form').addEventListener('submit',async event=>{event.preventDefault();const button=$('#login-submit');button.disabled=true;$('#login-error').textContent='';try{const password=$('#login-password').value;if(state.setup&&password!==$('#confirm-password').value)throw new Error('Passwords do not match.');const data={username:$('#login-username').value,password};if(state.setup)data.setup_code=$('#setup-code').value;await post(state.setup?'auth/setup':'auth/login',data);await initialize();}catch(e){$('#login-error').textContent=e.message;$('#login-password').value='';$('#confirm-password').value='';}finally{button.disabled=false;}});
$('#password-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.currentTarget;const values=Object.fromEntries(new FormData(form));const button=$('button[type=submit]',form);button.disabled=true;$('#password-error').textContent='';try{if(values.new_password!==values.confirm_password)throw new Error('Passwords do not match.');await post('auth/password',{current_password:values.current_password,new_password:values.new_password});form.reset();lock();$('#login-error').textContent='Password changed. Sign in again.';}catch(e){$('#password-error').textContent=e.message;}finally{button.disabled=false;}});
for(const page of ['discovery','traffic','events'])for(const control of $$(`#page-${page} .toolbar input,#page-${page} .toolbar select`)){control.addEventListener('input',()=>{clearTimeout(state.filterTimer);state.filterTimer=setTimeout(()=>refresh(),250);});}
$('#inventory-search').addEventListener('input',renderInventory);
window.addEventListener('hashchange',navigate);
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&state.authenticated)refresh();});
for(const name of ['pointerdown','keydown'])document.addEventListener(name,()=>{state.lastInteraction=Date.now();},{passive:true});
setInterval(()=>{if(state.authenticated&&Date.now()-state.lastInteraction>=30*60*1000){post('auth/logout').catch(()=>{});lock();$('#login-error').textContent='Signed out after 30 minutes without activity.';}else if(!document.hidden&&state.authenticated)refresh();},5000);
initialize();
