/* Yener Sitesi Fiber — site sayfası (index.html) ve yönetici sayfası (admin.html) ortak kodu.
   Veri: depodaki data.json. "public" kısmı herkese açık ev durumlarıdır;
   "private" kısmı (tutarlar, notlar, ödemeler, teklif) yönetici şifresiyle AES-GCM ile şifrelidir. */
(() => {
  const MODE = document.body.dataset.mode === 'admin' ? 'admin' : 'public';
  const REPO = 'HErkanuzun/yener-fiber', FILE = 'data.json', BRANCH = 'main';
  const API = `https://api.github.com/repos/${REPO}/contents/${FILE}`;
  const ITER = 250000;

  const $ = id => document.getElementById(id);
  const fmt = n => new Intl.NumberFormat('tr-TR',{style:'currency',currency:'TRY',maximumFractionDigits:0}).format(n||0);
  const fmt2 = n => new Intl.NumberFormat('tr-TR',{style:'currency',currency:'TRY',minimumFractionDigits:2,maximumFractionDigits:2}).format(n||0);
  const num = n => new Intl.NumberFormat('tr-TR').format(n);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
  const today = () => new Date().toISOString().slice(0,10);
  const when = iso => iso ? new Date(iso).toLocaleString('tr-TR',{day:'numeric',month:'long',year:'numeric',hour:'2-digit',minute:'2-digit'}) : '—';

  // Kapı numarası yatık S şeklinde: sol sütun aşağıdan yukarı (1–10), orta sütun yukarıdan aşağı (11–18), sağ sütun aşağıdan yukarı (19–28); her binada soldaki ev tek numara
  const BUILDINGS = [{x:545,y:24,w:165,h:96,r:-1.5},{x:110,y:24,w:165,h:96,r:0},{x:327,y:167,w:165,h:96,r:0},{x:545,y:310,w:165,h:96,r:1.5},{x:110,y:310,w:165,h:96,r:-1.5},{x:327,y:453,w:165,h:96,r:-1.5},{x:545,y:596,w:165,h:96,r:0},{x:110,y:596,w:165,h:96,r:1.5},{x:327,y:739,w:165,h:96,r:1.5},{x:545,y:882,w:165,h:96,r:-1.5},{x:110,y:882,w:165,h:96,r:0},{x:327,y:1025,w:165,h:96,r:0},{x:545,y:1168,w:165,h:96,r:1.5},{x:110,y:1168,w:165,h:96,r:-1.5}]
    .sort((a,b)=> a.x-b.x || (a.x===327 ? a.y-b.y : b.y-a.y));
  const aptLabel = n => `Kapı No ${n}`;
  const P_LABEL = {pending:'Karar bekliyor', yes:'Katılacak', backbone:'Sadece omurga maliyetine katılacak', no:'Katılmayacak'};
  const SUB_LABEL = {new:'Yeni abone olacak', tt:'Zaten Türk Telekom abonesi', switch:"Başka operatörden Türk Telekom'a geçecek", none:'İnternet almayacak, sadece evine kadar bağlatacak'};
  const SUB_SHORT = {new:'Yeni abone', tt:'Zaten TT abonesi', switch:"TT'ye geçecek", none:'Sadece bağlantı'};
  const PAY_LABEL = {full:'Ödemesi tamamlandı', partial:'Ödemenin bir kısmı yapıldı', none:'Henüz ödeme yok'};
  const payCat = r => { const p=+r.paid_amount||0, e=+r.expected_amount||0; return p<=0 ? 'none' : (p>=e ? 'full' : 'partial'); };
  const fillOf = (p,pay) => p==='no' ? 'var(--h-no)' : p==='backbone' ? 'var(--h-backbone)'
    : pay==='full' ? 'var(--h-full)' : pay==='partial' ? 'var(--h-partial)' : p==='yes' ? 'var(--h-yes)' : 'var(--h-pending)';
  const inkOf = (p,pay) => (p!=='no' && p!=='backbone' && (pay==='partial' || (pay==='none' && p!=='yes'))) ? 'var(--h-ink-dark)' : 'var(--h-ink-light)';
  const payLegend = pay => pay==='full' ? 'var(--h-full)' : pay==='partial' ? 'var(--h-partial)' : 'var(--h-pending)';

  let DATA = null;   // data.json
  let PRIV = null;   // çözülmüş özel kısım (sadece yönetici)
  let SHA = null, TOKEN = null, PASS = null;
  const ui = { q:'', filter:'all', busy:false, editing:null };

  // ---------- şifreleme ----------
  const te = new TextEncoder(), td = new TextDecoder();
  function b64e(buf){ const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf); let s=''; for (let i=0;i<b.length;i+=0x8000) s += String.fromCharCode.apply(null, b.subarray(i,i+0x8000)); return btoa(s); }
  const b64d = s => Uint8Array.from(atob(s.replace(/\s/g,'')), c => c.charCodeAt(0));
  async function keyFrom(pass, salt, iter){
    const base = await crypto.subtle.importKey('raw', te.encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:iter, hash:'SHA-256'}, base, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
  }
  async function encryptPriv(obj, pass){
    const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
    const k = await keyFrom(pass, salt, ITER);
    const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, k, te.encode(JSON.stringify(obj)));
    return {alg:'PBKDF2-SHA256+AES-GCM', iter:ITER, salt:b64e(salt), iv:b64e(iv), ct:b64e(ct)};
  }
  async function decryptPriv(p, pass){
    const k = await keyFrom(pass, b64d(p.salt), p.iter);
    const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:b64d(p.iv)}, k, b64d(p.ct));
    return JSON.parse(td.decode(pt));
  }

  // ---------- veri erişimi ----------
  function rec(n){ const r = PRIV && PRIV.apts[n]; return {participation:'pending', expected_amount:0, paid_amount:0, note:'', subscription:'', ...(r||{})}; }
  function house(n){
    if (MODE==='admin' && PRIV){ const r = rec(n); return {n, p:r.participation, pay:payCat(r), sub:r.subscription||'', rec:r}; }
    const h = (DATA && DATA.public && DATA.public.houses[n]) || {}; return {n, p:h.p||'pending', pay:h.pay||'none', sub:h.s||''};
  }
  function totals(){
    if (!(MODE==='admin' && PRIV)) return {paid:+(DATA?.public?.paid)||0, expected:+(DATA?.public?.expected)||0};
    let paid=0, expected=0;
    for (let n=1;n<=28;n++){ const r=rec(n); paid += +r.paid_amount||0; if (r.participation==='yes'||r.participation==='backbone') expected += +r.expected_amount||0; }
    return {paid, expected};
  }
  function counts(){ let yes=0, bb=0; for (let n=1;n<=28;n++){ const h=house(n); if(h.p==='yes') yes++; else if(h.p==='backbone') bb++; } return {yes, bb}; }
  function title(){ return (DATA?.public?.title) || 'Yener Sitesi Fiber Altyapı Yatırım Fonu'; }

  // Teklif hesapları (sadece yönetici; teklif özel kısımda)
  const T = () => PRIV.teklif;
  const lineTotal = it => Math.round(it[3]*it[4]*100)/100;
  const netA = () => T().A.reduce((s,it)=>s+lineTotal(it),0);
  const netB = () => T().B.reduce((s,it)=>s+lineTotal(it),0);
  const omurga = () => netA()*(1+T().kdv);
  const bagAll = () => netB()*(1+T().kdv);
  const bagEach = () => bagAll()/T().bag_houses;
  function costFor(yes, bb){ const N=yes+bb, sh = N>0 ? omurga()/N : 0; return {N, share:sh, full:sh+bagEach(), bb:sh, project: N>0 ? omurga()+bagEach()*yes : 0}; }

  function buildPublic(){
    const houses = {};
    for (let n=1;n<=28;n++){ const h=house(n); if (h.p!=='pending' || h.pay!=='none' || h.sub){ houses[n] = {p:h.p, pay:h.pay}; if (h.sub) houses[n].s = h.sub; } }
    return {title: title(), houses};   // tutarlar herkese açık kısma yazılmaz
  }

  // ---------- GitHub ----------
  async function ghGet(){
    const r = await fetch(`${API}?ref=${BRANCH}&t=${Date.now()}`, {headers:{Authorization:'Bearer '+TOKEN, Accept:'application/vnd.github+json'}, cache:'no-store'});
    if (r.status===401) throw {code:'token'};
    if (r.status===403 || r.status===404) throw {code:'access'};
    if (!r.ok) throw {code:'net'};
    const j = await r.json(); SHA = j.sha;
    return JSON.parse(td.decode(b64d(j.content)));
  }
  async function ghPut(obj, message){
    const r = await fetch(API, {method:'PUT', headers:{Authorization:'Bearer '+TOKEN, Accept:'application/vnd.github+json', 'Content-Type':'application/json'},
      body: JSON.stringify({message, content: b64e(te.encode(JSON.stringify(obj, null, 1)+'\n')), sha:SHA, branch:BRANCH})});
    if (r.status===409 || r.status===422) throw {code:'conflict'};
    if (r.status===401) throw {code:'token'};
    if (r.status===403 || r.status===404) throw {code:'access'};
    if (!r.ok) throw {code:'net'};
    const j = await r.json(); SHA = j.content.sha;
  }

  // ---------- ekran ----------
  let toastTimer;
  function toast(msg, ok){ const t=$('toast'); t.textContent=msg; t.classList.toggle('ok',!!ok); t.hidden=false; clearTimeout(toastTimer); toastTimer=setTimeout(()=>{t.hidden=true}, ok?3000:7000); }
  function setLive(kind, text){ if(!$('liveDot')) return; $('liveDot').className = 'live-dot' + (kind==='ok'?'':kind==='wait'?' wait':' off'); $('liveText').textContent = text; }
  const visible = h => (ui.filter==='all'||h.p===ui.filter) && (!ui.q || String(h.n)===ui.q);

  function renderMetrics(){
    const hs = Array.from({length:28},(_,i)=>house(i+1));
    const yes = hs.filter(h=>h.p==='yes').length, bb = hs.filter(h=>h.p==='backbone').length, no = hs.filter(h=>h.p==='no').length;
    const t = totals();
    $('mJoin').textContent = yes+bb; $('mMeter').style.width = `${(yes+bb)/28*100}%`;
    $('mJoinNote').textContent = `${yes} tam bağlantı · ${bb} sadece omurga`;
    if ($('mPaid')) $('mPaid').textContent = fmt(t.paid);
    if ($('mExpected')) $('mExpected').textContent = fmt(t.expected);
    $('mPending').textContent = 28-yes-bb-no; $('mNo').textContent = no;
    const sc = {new:0, tt:0, switch:0, none:0, unk:0};
    hs.forEach(h=>{ if (h.p==='yes'){ if (SUB_SHORT[h.sub]) sc[h.sub]++; else sc.unk++; } });
    if ($('subSummary')) $('subSummary').innerHTML = ['new','tt','switch','none'].map(k=>`<span><b>${sc[k]}</b> ${esc(SUB_SHORT[k])}</span>`).join('') + (sc.unk ? `<span class="muted"><b>${sc.unk}</b> belirtilmedi</span>` : '');
    $('projectTitle').textContent = title();
    $('updatedAt').textContent = DATA ? when(DATA.updated) : '—';
  }

  function renderPlan(){
    $('sitePlan').innerHTML = BUILDINGS.map((b,t)=>{
      const L=house(t*2+1), R=house(t*2+2), u=visible(L), d=visible(R);
      const f = `M 8 5 L ${b.w-12} 0 L ${b.w} 14 L ${b.w-5} ${b.h-8} L ${b.w-18} ${b.h} L 0 ${b.h-4} Z`;
      const half = (h,on,pts) => `<polygon points="${pts}" fill="${on?fillOf(h.p,h.pay):'var(--house-filtered)'}" pointer-events="${on?'auto':'none'}" stroke="#fff" stroke-width="3" role="button" tabindex="${on?0:-1}" aria-label="${esc(aptLabel(h.n)+': '+P_LABEL[h.p])}" data-apt="${h.n}"></polygon>`;
      const lab = (h,on,x) => `<text x="${x}" y="${b.h/2+7}" text-anchor="middle" class="roof-label" fill="${on?inkOf(h.p,h.pay):'#3c4658'}" opacity="${on?1:.25}">${h.n}</text>`;
      return `<g transform="translate(${b.x} ${b.y}) rotate(${b.r} ${b.w/2} ${b.h/2})">
        <path d="${f}" fill="var(--roof-shadow)" opacity=".35" transform="translate(4 5)"></path>
        <path d="${f}" fill="var(--roof-base)" stroke="var(--roof-edge)" stroke-width="2"></path>
        <clipPath id="roof-${t}"><path d="${f}"></path></clipPath>
        <g clip-path="url(#roof-${t})">${half(L,u,`0,0 ${b.w/2},0 ${b.w/2},${b.h} 0,${b.h}`)}${half(R,d,`${b.w/2},0 ${b.w},0 ${b.w},${b.h} ${b.w/2},${b.h}`)}</g>
        <path d="M ${b.w/2} 4 L ${b.w/2} ${b.h-3}" stroke="#fff" stroke-width="3" pointer-events="none"></path>
        ${lab(L,u,b.w/4)}${lab(R,d,b.w*.75)}
        <text x="${b.w/2}" y="${b.h+20}" text-anchor="middle" class="building-label">${t+1}. BİNA</text>
      </g>`;
    }).join('');
  }

  function renderLists(){
    if (MODE!=='admin' || !PRIV) return;
    const act = PRIV.activity || [];
    $('activityList').innerHTML = act.length===0 ? '<p class="muted">Henüz işlem kaydı yok.</p>'
      : '<ul>' + act.slice(0,40).map(e=>`<li><span class="history-dot"></span><span>${esc(e.message)}</span><time>${esc(new Date(e.created_at).toLocaleString('tr-TR'))}</time></li>`).join('') + '</ul>';
    const pays = PRIV.payments || [];
    $('paymentList').innerHTML = pays.length===0 ? '<p class="muted">Henüz ödeme kaydı eklenmedi.</p>'
      : '<div class="payment-list">' + pays.map(p=>`<div><span><b>${esc(aptLabel(p.apartment_no))}</b><small>${esc(p.paid_on||'')}${p.note?' · '+esc(p.note):''}</small></span><strong>${esc(fmt(p.amount))}</strong></div>`).join('') + '</div>';
    const proj = costFor(counts().yes, counts().bb).project, t = totals();
    $('fTotal').textContent = fmt(proj); $('fPaid').textContent = fmt(t.paid); $('fLeft').textContent = fmt(Math.max(0, proj-t.paid));
  }

  const calc = { yes:null, bb:null };
  function calcCounts(){
    const c = counts();
    const auto = (c.yes+c.bb)===0 ? {yes:T().bag_houses, bb:0, fromTeklif:true} : {...c, fromTeklif:false};
    return { yes: calc.yes ?? auto.yes, bb: calc.bb ?? auto.bb, manual: calc.yes!=null || calc.bb!=null, fromTeklif:auto.fromTeklif, cur:c };
  }
  function renderCosts(){
    if (MODE!=='admin' || !PRIV) return;
    const NA=netA(), NB=netB(), KDV=T().kdv, OM=omurga(), BA=bagAll(), BE=bagEach();
    $('cOmurga').textContent = fmt2(OM); $('cOmurgaNet').textContent = `KDV hariç ${fmt2(NA)} · ${T().A.length} kalem`;
    $('cBag').textContent = fmt2(BA); $('cBagNet').textContent = `KDV hariç ${fmt2(NB)} · ev başı ort. ${fmt2(BE)}`;
    $('cTotal').textContent = fmt2(OM+BA); $('cTotalNet').textContent = `KDV hariç ${fmt2(NA+NB)} · %50 peşinat ${fmt2((OM+BA)/2)}`;
    const k = calcCounts();
    if (document.activeElement!==$('calcYes')) $('calcYes').value = k.yes;
    if (document.activeElement!==$('calcBb')) $('calcBb').value = k.bb;
    $('calcReset').hidden = !k.manual;
    $('calcSource').textContent = k.manual ? `Deneme hesabı. Evlerin güncel durumu: ${k.cur.yes} tam bağlantı, ${k.cur.bb} sadece omurga.`
      : k.fromTeklif ? 'Henüz hiçbir eve katılım işlenmedi; teklifteki 17 ev esas alındı.' : 'Evlerin güncel durumundan alındı.';
    const c = costFor(k.yes, k.bb);
    $('pShare').textContent = c.N ? fmt2(c.share) : '—';
    $('pBag').textContent = fmt2(BE);
    $('pFull').textContent = c.N ? fmt2(c.full) : '—';
    $('pBb').textContent = c.N ? fmt2(c.bb) : '—';
    $('pProject').textContent = c.N ? fmt2(c.project) : '—';
    if (c.N>0 && c.N<28){ const nx = costFor(k.yes, k.bb+1); $('pNext').textContent = `Bir ev daha katılırsa (${c.N+1} ev) omurga payı ${fmt2(nx.share)} olur; herkesin payı ${fmt2(c.share-nx.share)} düşer.`; $('pNext').hidden=false; }
    else $('pNext').hidden = true;
    const rows=[], from = Math.max(1, Math.min(c.N||17, 28) - 4);
    for (let N=from; N<=28; N++){ const sh=OM/N, prev = N>1 ? OM/(N-1) : null;
      rows.push(`<tr class="${N===c.N?'cur':N===c.N+1?'next':''}"><td>${N} ev${N===c.N?' · şu an':N===c.N+1?' · +1 ev':''}</td><td class="num">${fmt2(sh)}</td><td class="num">${fmt2(sh+BE)}</td><td class="num">${prev?'−'+fmt2(prev-sh):'—'}</td></tr>`); }
    $('scenarioBody').innerHTML = rows.join('');
    const PER_M = T().per_m, FIXED = (NB - T().drop_m*PER_M)/T().bag_houses;
    $('lengthBody').innerHTML = [40,45,60,70,75,80].map(L=>{ const net = FIXED + PER_M*L; return `<tr><td>${L} m</td><td class="num">${fmt2(net)}</td><td class="num">${fmt2(net*(1+KDV))}</td></tr>`; }).join('');
    $('lengthNote').textContent = `Hesap: ev başına sabit ${fmt2(FIXED)} (klemp, kanca, klips, bina girişi, füzyon eki) + metre başına ${fmt2(PER_M)} (drop kablo + çekim), KDV hariç. Projedeki kablo boyları 40–80 m arası. Kişi başı fiyatlarda 17 evin ortalaması kullanıldı.`;
    const itemRows = list => list.map(it=>`<tr><td class="pos">${esc(it[0])}</td><td>${esc(it[1])}</td><td class="num">${num(it[3])} ${esc(it[2])}</td><td class="num">${it[4]?fmt2(it[4]):'dahil'}</td><td class="num">${it[4]?fmt2(lineTotal(it)):'dahil'}</td></tr>`).join('');
    const foot = net => `<tr><td></td><td>Toplam (KDV hariç)</td><td></td><td></td><td class="num">${fmt2(net)}</td></tr><tr><td></td><td>KDV %20</td><td></td><td></td><td class="num">${fmt2(net*KDV)}</td></tr><tr><td></td><td>Toplam (KDV dahil)</td><td></td><td></td><td class="num">${fmt2(net*(1+KDV))}</td></tr>`;
    $('itemsA').innerHTML = itemRows(T().A); $('footA').innerHTML = foot(NA);
    $('itemsB').innerHTML = itemRows(T().B); $('footB').innerHTML = foot(NB);
    $('sumA').textContent = fmt2(OM); $('sumB').textContent = fmt2(BA);
  }

  // Gider grupları (poz koduna göre)
  const GROUP_OF = {'ANA-M01':'kablo','YEN-M01':'kablo','ANA-M02':'direk','ANA-M03':'direk','ANA-M04':'direk','ANA-M05':'direk','ANA-M06':'direk','ANA-İ01':'direk','ANA-İ02':'direk',
    'ANA-M07':'fdk','ANA-M08':'fdk','ANA-M09':'fdk','ANA-İ07':'fdk','ANA-M10':'gergi','YEN-M02':'gergi','YEN-M03':'gergi','YEN-M04':'gergi','YEN-İ02':'gergi','YEN-İ03':'gergi',
    'ANA-M11':'menhol','ANA-M12':'menhol','ANA-İ03':'menhol','ANA-İ04':'menhol','ANA-İ05':'menhol','ANA-İ06':'cekim','YEN-İ01':'cekim',
    'YEN-M05':'cephe','YEN-M06':'cephe','YEN-İ04':'cephe','YEN-M07':'giris','YEN-İ05':'giris',
    'ANA-M13':'ek','ANA-M14':'ek','ANA-İ08':'ek','YEN-M08':'ek','YEN-M09':'ek','YEN-İ06':'ek','ANA-İ09':'test','ANA-İ10':'test','YEN-İ07':'test','YEN-İ08':'test'};
  const GROUP_NAME = {direk:'Direkler (malzeme + dikim/montaj)', cekim:'Kablo çekim işçiliği (ana hat + evlere)', kablo:'Fiber kablo (malzeme)', giris:'Ev girişleri (duvar delme, boru, izolasyon)',
    gergi:'Gergi, klemp ve kancalar (malzeme + montaj)', cephe:'Cephe klipsleri (malzeme + montaj)', ek:'Füzyon ekleri ve etiketler', fdk:'Dağıtım kutuları ve splitter', menhol:'Menhol çıkışı ve yeraltı geçişi', test:'Ölçüm, test ve belgeler'};
  function renderAnalysis(){
    if (MODE!=='admin' || !PRIV) return;
    const KDV = T().kdv;
    const items = [...T().A.map(it=>({it, sec:'om'})), ...T().B.map(it=>({it, sec:'bag'}))].map(x=>({...x, net:lineTotal(x.it), isc:/-İ/.test(x.it[0])}));
    const total = items.reduce((s,x)=>s+x.net,0), mal = items.filter(x=>!x.isc).reduce((s,x)=>s+x.net,0), isc = total-mal, kdv = total*KDV, gross = total+kdv;
    const pct = v => total ? (v/total*100).toLocaleString('tr-TR',{minimumFractionDigits:1,maximumFractionDigits:1})+'%' : '—';
    $('gMal').textContent = fmt2(mal); $('gMalP').textContent = `KDV hariç toplamın ${pct(mal)}'i · KDV dahil ${fmt2(mal*(1+KDV))}`;
    $('gIsc').textContent = fmt2(isc); $('gIscP').textContent = `KDV hariç toplamın ${pct(isc)}'i · KDV dahil ${fmt2(isc*(1+KDV))}`;
    $('gKdv').textContent = fmt2(kdv);
    $('gTop').textContent = fmt2(gross); $('gTopP').textContent = `KDV hariç ${fmt2(total)}`;
    $('gSplit').innerHTML = `<i class="s-mal" style="width:${mal/gross*100}%" title="Malzeme"></i><i class="s-isc" style="width:${isc/gross*100}%" title="İşçilik"></i><i class="s-kdv" style="width:${kdv/gross*100}%" title="KDV"></i>`;
    const groups = {}; items.forEach(x=>{ const g = GROUP_OF[x.it[0]] || 'ek'; groups[g] = (groups[g]||0) + x.net; });
    const gs = Object.entries(groups).sort((a,b)=>b[1]-a[1]); const gmax = gs.length ? gs[0][1] : 1;
    $('groupBody').innerHTML = gs.map(([g,v])=>`<tr class="${v?'':'zero'}"><td>${esc(GROUP_NAME[g]||g)}</td><td class="num">${v?fmt2(v):'dahil'}</td><td class="num">${v?fmt2(v*(1+KDV)):'—'}</td><td class="num">${v?pct(v):'—'}</td><td><div class="bar-track"><i style="width:${v/gmax*100}%"></i></div></td></tr>`).join('');
    const sorted = [...items].sort((a,b)=>b.net-a.net); const imax = sorted[0]?.net || 1;
    $('allItemsBody').innerHTML = sorted.map((x,i)=>{ const it=x.it; return `<tr class="${x.net?'':'zero'}"><td>${i+1}</td><td class="pos">${esc(it[0])}</td><td>${esc(it[1])}</td>
      <td><span class="tag ${x.sec}">${x.sec==='om'?'Omurga':'Ev bağlantısı'}</span></td><td><span class="tag ${x.isc?'isc':'mal'}">${x.isc?'İşçilik':'Malzeme'}</span></td>
      <td class="num">${num(it[3])} ${esc(it[2])} × ${it[4]?fmt2(it[4]):'dahil'}</td><td class="num">${x.net?fmt2(x.net):'dahil'}</td><td class="num">${x.net?fmt2(x.net*KDV):'—'}</td><td class="num">${x.net?fmt2(x.net*(1+KDV)):'—'}</td>
      <td class="num">${x.net?pct(x.net):'—'}</td><td><div class="bar-track"><i class="${x.isc?'isc':''}" style="width:${x.net/imax*100}%"></i></div></td></tr>`; }).join('');
    $('allItemsFoot').innerHTML = `<tr><td></td><td></td><td>Toplam (${items.length} kalem)</td><td></td><td></td><td></td><td class="num">${fmt2(total)}</td><td class="num">${fmt2(kdv)}</td><td class="num">${fmt2(gross)}</td><td class="num">100%</td><td></td></tr>`;
  }
  function suggestedFor(n, part){
    const c = counts(), was = house(n).p; let yes=c.yes, bb=c.bb;
    if (was==='yes') yes--; else if (was==='backbone') bb--;
    if (part==='yes') yes++; else if (part==='backbone') bb++;
    const r = costFor(yes, bb); return part==='yes' ? r.full : part==='backbone' ? r.bb : 0;
  }
  function renderSuggest(){
    if (ui.editing==null || MODE!=='admin') return;
    const v = suggestedFor(ui.editing, $('edPart').value);
    $('edSuggestText').textContent = v>0 ? `Güncel katılımla önerilen: ${fmt2(v)}` : 'Bu durum için katkı payı önerilmez.';
    $('edSuggest').hidden = !(v>0);
  }

  function renderAll(){
    if (!DATA) return;
    renderMetrics(); renderPlan(); renderLists(); renderCosts(); renderAnalysis();
    if (MODE==='admin' && PRIV && document.activeElement!==$('setTitle')) $('setTitle').value = title();
  }

  // ---------- ev penceresi ----------
  let lastFocus = null;
  function openModal(n){
    const h = house(n); ui.editing = n; lastFocus = document.activeElement;
    $('editTitle').textContent = `${aptLabel(n)} · ${Math.ceil(n/2)}. bina ${n%2?'sol':'sağ'} ev`;
    if (MODE==='admin'){
      const r = h.rec;
      $('edPart').value = r.participation; $('edExpected').value = r.expected_amount ?? 0;
      $('edPaid').value = r.paid_amount ?? 0; $('edNote').value = r.note || '';
      $('edSub').value = r.subscription || '';
      renderSuggest();
    } else {
      $('viewRows').innerHTML =
        `<div class="status-row"><span>Katılım</span><b><i style="background:${fillOf(h.p,h.p==='yes'?'none':h.pay)}"></i>${esc(P_LABEL[h.p])}</b></div>` +
        (h.p==='no' || (h.p==='pending' && h.pay==='none') ? '' : `<div class="status-row"><span>Ödeme</span><b><i style="background:${payLegend(h.pay)}"></i>${esc(PAY_LABEL[h.pay])}</b></div>`) +
        (h.sub ? `<div class="status-row"><span>Abonelik</span><b>${esc(SUB_LABEL[h.sub])}</b></div>` : '');
    }
    $('modal').hidden = false; (MODE==='admin' ? $('edPart') : $('modalClose')).focus();
  }
  function closeModal(){ $('modal').hidden = true; ui.editing = null; if (lastFocus && lastFocus.focus) lastFocus.focus(); }

  $('search').addEventListener('input', e=>{ ui.q = e.target.value.trim(); renderPlan(); });
  $('filter').addEventListener('change', e=>{ ui.filter = e.target.value; renderPlan(); });
  $('sitePlan').addEventListener('click', e=>{ const p=e.target.closest('[data-apt]'); if(p) openModal(+p.dataset.apt); });
  $('sitePlan').addEventListener('keydown', e=>{ const p=e.target.closest('[data-apt]'); if(p && (e.key==='Enter'||e.key===' ')){ e.preventDefault(); openModal(+p.dataset.apt); } });
  $('modalClose').addEventListener('click', closeModal);
  $('modal').addEventListener('click', e=>{ if(e.target===$('modal')) closeModal(); });
  document.addEventListener('keydown', e=>{ if(e.key==='Escape' && !$('modal').hidden) closeModal(); });

  // ================= SİTE SAYFASI =================
  if (MODE==='public'){
    async function load(){
      setLive('wait','Güncelleniyor…');
      try {
        let r = await fetch(`${API}?ref=${BRANCH}&t=${Date.now()}`, {headers:{Accept:'application/vnd.github.raw+json'}, cache:'no-store'});
        if (!r.ok) r = await fetch(`${FILE}?t=${Date.now()}`, {cache:'no-store'});
        if (!r.ok) throw 0;
        DATA = await r.json(); renderAll(); setLive('ok','Son güncelleme');
      } catch { setLive('off', DATA ? 'Son güncelleme (bağlantı yok)' : 'Bilgiler yüklenemedi, sayfayı yenileyin'); }
    }
    load();
    setInterval(()=>{ if (document.visibilityState==='visible') load(); }, 120000);
    document.addEventListener('visibilitychange', ()=>{ if (document.visibilityState==='visible') load(); });
    return;
  }

  // ================= YÖNETİCİ SAYFASI =================
  const store = {
    get(k){ try { return localStorage.getItem(k); } catch { return null; } },
    set(k,v){ try { localStorage.setItem(k,v); } catch {} },
    del(k){ try { localStorage.removeItem(k); } catch {} },
  };
  function setSave(kind, text){ $('saveDot').className = 'live-dot' + (kind==='ok'?'':kind==='wait'?' wait':' off'); $('saveText').textContent = text; }
  function setBusy(b){ ['setSave','edSave','passSave','paySave'].forEach(id=>{ if($(id)) $(id).disabled = b || (id==='paySave' && !$('payAmount').value); }); }

  async function unlock(token, pass, remember){
    TOKEN = token.trim();
    const data = await ghGet();
    try {
      const rr = await fetch(`https://api.github.com/repos/${REPO}`, {headers:{Authorization:'Bearer '+TOKEN, Accept:'application/vnd.github+json'}, cache:'no-store'});
      if (rr.ok){ const j = await rr.json(); if (j.permissions && j.permissions.push === false) throw {code:'readonly'}; }
    } catch(e){ if (e && e.code==='readonly') throw e; }
    let priv;
    try { priv = await decryptPriv(data.private, pass); } catch { throw {code:'pass'}; }
    DATA = data; PRIV = priv; PASS = pass;
    PRIV.apts ||= {}; PRIV.payments ||= []; PRIV.activity ||= [];
    if (remember){ store.set('yf_token', TOKEN); store.set('yf_pass', PASS); }
    $('loginView').hidden = true; $('appView').hidden = false; $('logout').hidden = false; $('qrTop').hidden = false;
    setSave('ok', 'Son kayıt: ' + when(DATA.updated));
    renderAll();
  }
  function loginError(e){
    $('loginErr').textContent =
      e.code==='pass' ? 'Yönetici şifresi yanlış.' :
      e.code==='token' ? 'GitHub anahtarı geçersiz veya süresi dolmuş.' :
      e.code==='access' ? 'Bu GitHub anahtarının yener-fiber deposuna erişimi yok.' :
      e.code==='readonly' ? 'Bu GitHub anahtarı sadece okuyabiliyor, kaydedemez. Yazma izni olan yeni bir anahtar oluştur.' :
      'Bağlanılamadı. İnternet bağlantını kontrol et.';
  }
  $('loginForm').addEventListener('submit', async e=>{
    e.preventDefault(); $('loginErr').textContent=''; $('loginBtn').disabled = true; $('loginBtn').textContent = 'Giriş yapılıyor…';
    try { await unlock($('lgToken').value, $('lgPass').value, $('lgRemember').checked); }
    catch(err){ TOKEN=null; loginError(err); }
    finally { $('loginBtn').disabled = false; $('loginBtn').textContent = 'Giriş yap'; }
  });
  $('logout').addEventListener('click', ()=>{ store.del('yf_token'); store.del('yf_pass'); location.reload(); });

  async function commit(mutate, message, okMsg, newPass){
    if (ui.busy) return false;
    ui.busy = true; setBusy(true); setSave('wait','Kaydediliyor…');
    const backup = JSON.stringify(PRIV), backupData = DATA;
    try {
      mutate(PRIV);
      PRIV.activity.unshift({message, created_at:new Date().toISOString()});
      PRIV.activity = PRIV.activity.slice(0, 300);
      const next = {v:2, updated:new Date().toISOString(), public: buildPublic(), private: await encryptPriv(PRIV, newPass || PASS)};
      if (mutate.title) next.public.title = mutate.title;
      await ghPut(next, message);
      DATA = next; if (newPass){ PASS = newPass; if (store.get('yf_pass')) store.set('yf_pass', newPass); }
      setSave('ok','Kaydedildi · site sayfası güncellendi'); toast(okMsg, true);
      return true;
    } catch(e){
      PRIV = JSON.parse(backup); DATA = backupData;
      if (e.code==='conflict'){ toast('Kayıtlar başka bir yerden değişmiş. Son hâli yüklendi, işlemi tekrar yap.'); try { DATA = await ghGet(); PRIV = await decryptPriv(DATA.private, PASS); } catch {} }
      else if (e.code==='token') toast('GitHub anahtarının süresi dolmuş ya da geçersiz. Sağ üstten Çıkış yapıp yeni anahtarla gir.');
      else if (e.code==='access') toast('Bu GitHub anahtarının yazma izni yok. Sağ üstten Çıkış yapıp yazma izni olan yeni anahtarla gir.');
      else toast('Kaydedilemedi. İnternet bağlantını kontrol edip tekrar dene.');
      setSave('off','Son işlem kaydedilmedi');
      return false;
    } finally { ui.busy = false; setBusy(false); renderAll(); }
  }

  $('editForm').addEventListener('submit', async e=>{
    e.preventDefault(); if (ui.editing==null) return;
    const n = ui.editing, part = $('edPart').value;
    const body = {participation:part, expected_amount:+$('edExpected').value||0, paid_amount:+$('edPaid').value||0, subscription:$('edSub').value, note:$('edNote').value.trim()};
    const ok = await commit(P => { P.apts[n] = body; }, `${aptLabel(n)}: ${P_LABEL[part]}`, 'Ev kaydı kaydedildi.');
    if (ok) closeModal();
  });
  $('edPart').addEventListener('change', renderSuggest);
  $('edSuggest').addEventListener('click', ()=>{ const v = suggestedFor(ui.editing, $('edPart').value); if (v>0) $('edExpected').value = Math.round(v*100)/100; });

  $('payAmount').addEventListener('input', ()=>{ $('paySave').disabled = ui.busy || !$('payAmount').value; });
  $('payForm').addEventListener('submit', async e=>{
    e.preventDefault();
    const n = +$('payApt').value, amount = +$('payAmount').value; if (!(amount>0)) return;
    const pay = {apartment_no:n, amount, paid_on:$('payDate').value || today(), note:$('payNote').value.trim(), created_at:new Date().toISOString()};
    const ok = await commit(P => { P.payments.unshift(pay); const r = rec(n); P.apts[n] = {...r, paid_amount:(+r.paid_amount||0)+amount}; },
      `${aptLabel(n)} için ${fmt(amount)} ödeme kaydedildi`, 'Ödeme kaydedildi.');
    if (ok){ $('payAmount').value=''; $('payNote').value=''; $('paySave').disabled = true; }
  });

  $('settingsForm').addEventListener('submit', async e=>{
    e.preventDefault();
    const t = $('setTitle').value.trim() || 'Yener Sitesi Fiber Altyapı Yatırım Fonu';
    const m = () => {}; m.title = t;
    await commit(m, 'Proje adı güncellendi', 'Proje adı kaydedildi.');
  });
  $('passForm').addEventListener('submit', async e=>{
    e.preventDefault();
    const a = $('passNew').value, b = $('passNew2').value;
    if (a.length < 8){ toast('Yeni şifre en az 8 karakter olmalı.'); return; }
    if (a !== b){ toast('Yeni şifreler birbirini tutmuyor.'); return; }
    const ok = await commit(()=>{}, 'Yönetici şifresi değiştirildi', 'Şifre değiştirildi. Bundan sonra yeni şifreyle gir.', a);
    if (ok){ $('passNew').value=''; $('passNew2').value=''; }
  });

  ['calcYes','calcBb'].forEach(id => $(id).addEventListener('input', e=>{
    const v = e.target.value, val = v==='' ? null : Math.max(0, Math.min(28, Math.floor(+v)));
    const k = calcCounts(); calc.yes = id==='calcYes' ? val : (calc.yes ?? k.yes); calc.bb = id==='calcBb' ? val : (calc.bb ?? k.bb);
    renderCosts();
  }));
  $('calcReset').addEventListener('click', ()=>{ calc.yes=null; calc.bb=null; renderCosts(); });

  // Telefona aktarma: anahtar QR içinde #t= ile gelir; adres çubuğundan hemen silinir
  (() => {
    const m = location.hash.match(/^#t=([^&]+)/);
    if (m){ try { $('lgToken').value = decodeURIComponent(m[1]); } catch {} history.replaceState(null, '', location.pathname); setTimeout(()=>$('lgPass').focus(), 50); }
  })();
  $('qrTop').addEventListener('click', ()=>{ if ($('qrBox').hidden) $('qrBtn').click(); $('qrBox').scrollIntoView({behavior:'smooth', block:'center'}); });
  let qrTimer;
  $('qrBtn').addEventListener('click', ()=>{
    const box = $('qrBox');
    if (!box.hidden){ box.hidden = true; $('qrNote').hidden = true; $('qrBtn').textContent = 'QR kodu göster'; clearTimeout(qrTimer); return; }
    if (typeof QRCode === 'undefined'){ toast('QR kodu oluşturulamadı. Sayfayı yenileyip tekrar dene.'); return; }
    box.innerHTML = ''; new QRCode(box, {text: location.origin + location.pathname + '#t=' + encodeURIComponent(TOKEN), width:240, height:240, correctLevel: QRCode.CorrectLevel.M});
    box.hidden = false; $('qrNote').hidden = false; $('qrBtn').textContent = 'QR kodu gizle';
    clearTimeout(qrTimer); qrTimer = setTimeout(()=>{ box.hidden = true; box.innerHTML=''; $('qrNote').hidden = true; $('qrBtn').textContent = 'QR kodu göster'; }, 120000);
  });

  $('payApt').innerHTML = Array.from({length:28},(_,i)=>`<option value="${i+1}">${esc(aptLabel(i+1))}</option>`).join('');
  $('payDate').value = today();

  (async () => {
    const t = store.get('yf_token'), p = store.get('yf_pass');
    if (t && p){
      $('loginBtn').disabled = true; $('loginBtn').textContent = 'Giriş yapılıyor…';
      try { await unlock(t, p, false); }
      catch(e){ loginError(e); $('lgToken').value = t; }
      finally { $('loginBtn').disabled = false; $('loginBtn').textContent = 'Giriş yap'; }
    }
  })();
})();
