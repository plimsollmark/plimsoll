import {nodes, providers, categories, paths, pathSteps, connections} from './architecture-model.mjs';

const $ = id => document.getElementById(id);
const svgNS = 'http://www.w3.org/2000/svg';
const types = {request:'Request / control', authority:'Authority / setup', api:'API call', response:'Response', deny:'Failure / refusal', observe:'Observation'};
const state = {path:paths[0], provider:'runsc', index:0, node:null, filter:'all', playing:false};
let timer;
let animation;
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const effectiveProvider = () => state.path.fixedProvider || state.provider;
const words = value => String(value).replace(/\{\{(\w+)\}\}/g, (_, key) => providers[effectiveProvider()][key] ?? key);
const html = value => escape(words(value));
const sequence = () => pathSteps(state.path, effectiveProvider());
const current = () => sequence()[state.index];

function svg(tag, attrs = {}, text) {
  const el = document.createElementNS(svgNS, tag);
  for (const [key, value] of Object.entries(attrs)) el.setAttribute(key, value);
  if (text !== undefined) el.textContent = words(text);
  return el;
}

function stop() {
  state.playing = false;
  clearTimeout(timer);
  $('play').textContent = 'Play path';
  $('play').setAttribute('aria-pressed', 'false');
}

function save(replace = false) {
  const params = new URLSearchParams({path:state.path.id, provider:state.provider, step:String(state.index + 1)});
  if (state.node) params.set('node', state.node);
  const hash = `#${params}`;
  if (location.hash !== hash) history[replace ? 'replaceState' : 'pushState'](null, '', hash);
}

function restore() {
  stop();
  const params = new URLSearchParams(location.hash.slice(1));
  state.path = paths.find(path => path.id === params.get('path')) || paths[0];
  const requested = params.get('provider');
  state.provider = Object.hasOwn(providers, requested) && requested !== 'disabled' ? requested : 'runsc';
  const index = Number(params.get('step')) - 1;
  state.index = Number.isSafeInteger(index) ? Math.max(0, Math.min(sequence().length - 1, index)) : 0;
  state.node = Object.hasOwn(nodes, params.get('node')) ? params.get('node') : null;
  state.filter = 'all';
  render();
  revealCurrent();
}

function choose(path, index = 0, provider = state.provider) {
  stop();
  state.path = path;
  state.provider = provider;
  state.index = Math.min(index, sequence().length - 1);
  state.node = null;
  state.filter = 'all';
  save();
  render();
}

function move(index, auto = false) {
  if (!auto) stop();
  state.index = Math.max(0, Math.min(sequence().length - 1, index));
  state.node = null;
  save(auto);
  render();
  revealCurrent();
}

function inspect(id) {
  stop();
  state.node = id;
  state.filter = 'all';
  save();
  render();
  $('announcement').textContent = `${nodes[id].name}. Component details and incoming and outgoing connections are in the inspector.`;
  if (matchMedia('(max-width: 900px)').matches) $('nodeInspector').scrollIntoView({block:'start',behavior:reducedMotion.matches ? 'instant' : 'smooth'});
}

function revealCurrent() {
  const timeline = $('stepTimeline');
  const item = timeline.querySelector('[aria-current="step"]');
  if (item) timeline.scrollTo({left:item.parentElement.offsetLeft - timeline.offsetLeft - 10, behavior:reducedMotion.matches ? 'instant' : 'smooth'});
  // Move only the map's own scroll area, never the document or user's reading position.
  const map = $('architectureMap');
  const scroller = $('mapScroll');
  if (scroller.scrollWidth > scroller.clientWidth) {
    const target = nodes[current().to];
    const scale = map.getBoundingClientRect().width / 1010;
    scroller.scrollTo({left:(target.x + 90) * scale - scroller.clientWidth / 2, behavior:reducedMotion.matches ? 'instant' : 'smooth'});
  }
}

function port(node, toward) {
  const center = [node.x + 90, node.y + 38];
  const dx = toward[0] - center[0], dy = toward[1] - center[1];
  if (Math.abs(dx) / 90 > Math.abs(dy) / 38) return [node.x + (dx > 0 ? 182 : -2), center[1]];
  return [center[0], node.y + (dy > 0 ? 78 : -2)];
}

function route(step) {
  const a = nodes[step.from], b = nodes[step.to];
  const ac = [a.x + 90, a.y + 38], bc = [b.x + 90, b.y + 38];
  const via = step.via || [];
  const start = port(a, via[0] || bc), end = port(b, via.at(-1) || ac);
  let points = [start, ...via, end];
  if (!via.length && start[0] !== end[0] && start[1] !== end[1]) {
    const middle = (start[1] + end[1]) / 2;
    points = [start, [start[0], middle], [end[0], middle], end];
  }
  return points.map((p, i) => `${i ? 'L' : 'M'}${p[0]} ${p[1]}`).join(' ');
}

function renderMap() {
  cancelAnimationFrame(animation);
  const map = $('architectureMap');
  const focusedNode = document.activeElement?.getAttribute('data-node');
  map.replaceChildren();
  const defs = svg('defs');
  for (const kind of [...Object.keys(types), 'faint']) {
    const marker = svg('marker', {id:`arrow-${kind}`, viewBox:'0 0 10 10', refX:9, refY:5, markerWidth:6, markerHeight:6, orient:'auto'});
    marker.append(svg('path', {d:'M1 1 L9 5 L1 9 Z', fill:kind === 'faint' ? '#cedbe1' : `var(--${kind})`}));
    defs.append(marker);
  }
  map.append(defs);
  map.append(svg('path', {d:effectiveProvider() === 'wasm' ? 'M265 65 H997 V587 H265 Z' : 'M265 65 H997 V438 H750 V587 H265 Z', class:'host-boundary'}));
  map.append(svg('rect', {x:766, y:455, width:231, height:132, rx:10, class:'guest-boundary'}));
  map.append(svg('text', {x:977,y:84,class:'map-region','text-anchor':'end'}, 'PLIMSOLLD · TRUSTED GO CODE'));
  map.append(svg('text', {x:785,y:583,class:'map-region guest-region'}, effectiveProvider() === 'wasm' ? 'GUEST · SAME PROCESS' : effectiveProvider() === 'disabled' ? 'NO GUEST STARTS' : 'GUEST · {{tier}} TIER'));
  map.append(svg('text', {x:25,y:84,class:'map-region'}, 'YOUR APPLICATION'));
  map.append(svg('text', {x:25,y:280,class:'map-region'}, 'OPERATIONS'));
  map.append(svg('text', {x:25,y:482,class:'map-region'}, 'CUSTOMER SYSTEM'));
  const list = sequence(), active = current();
  const usedNodes = new Set(list.flatMap(step => [step.from,step.to]));
  const lines = svg('g', {'aria-hidden':'true'});
  const unique = new Map();
  list.forEach((step, index) => unique.set(route(step), {step,index}));
  for (const {step,index} of unique.values()) {
    lines.append(svg('path', {d:route(step),class:`route-line ${index < state.index ? 'done' : 'faint'} ${step.kind}`,'marker-end':'url(#arrow-faint)'}));
  }
  const activeLine = svg('path', {id:'activeConnection',d:route(active),class:`route-line active ${active.kind}`,'marker-end':`url(#arrow-${active.kind})`,'data-from':active.from,'data-to':active.to,'data-step':active.id});
  lines.append(activeLine);
  map.append(lines);
  Object.entries(nodes).forEach(([id,node], index) => {
    const endpoint = id === active.from || id === active.to;
    const group = svg('g', {class:`graph-node ${usedNodes.has(id) ? '' : 'inactive'} ${endpoint ? `endpoint ${active.kind}` : ''} ${id === active.to ? 'to' : ''} ${state.node === id ? 'selected' : ''}`,role:'button',tabindex:0,'data-node':id,'aria-label':`${node.name}. ${words(node.role)} Inspect incoming and outgoing connections.`,'aria-pressed':String(state.node === id)});
    group.append(svg('title', {}, `${node.name}: ${words(node.role)}`));
    group.append(svg('rect',{x:node.x,y:node.y,width:180,height:76,class:'node-card'}));
    group.append(svg('text',{x:node.x+14,y:node.y+17,class:'node-index'},String(index+1).padStart(2,'0')));
    group.append(svg('text',{x:node.x+14,y:node.y+39,class:'node-name'},node.name));
    group.append(svg('text',{x:node.x+14,y:node.y+59,class:'node-sub'},node.sub));
    if (endpoint) group.append(svg('circle',{cx:node.x+165,cy:node.y+15,r:3,class:'node-dot'}));
    group.addEventListener('click', () => inspect(id));
    group.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {event.preventDefault();event.stopPropagation();inspect(id);}
    });
    map.append(group);
  });
  const packet = svg('circle', {r:5,class:`packet ${active.kind}`,'aria-hidden':'true'});
  map.append(packet);
  const length = activeLine.getTotalLength();
  const position = fraction => {
    const p = activeLine.getPointAtLength(length * fraction);
    packet.setAttribute('cx', p.x); packet.setAttribute('cy', p.y);
  };
  position(.6);
  if (!reducedMotion.matches && !state.node) {
    const start = performance.now();
    const animate = now => {
      const progress = Math.min(1,(now-start)/850);
      position(.07 + progress * .53);
      if (progress < 1) animation = requestAnimationFrame(animate);
    };
    animation = requestAnimationFrame(animate);
  }
  if (focusedNode) map.querySelector(`[data-node="${focusedNode}"]`)?.focus({preventScroll:true});
}

function renderStep() {
  const step = current();
  $('stepInspector').innerHTML = `<div class="inspection-content ${step.kind}">
    <div class="step-label"><span>CONNECTION ${String(state.index+1).padStart(2,'0')}</span><span class="type-tag">${types[step.kind]}</span></div>
    <h2>${html(step.title)}</h2>
    <div class="from-to"><button type="button" data-inspect="${step.from}">${html(nodes[step.from].name)}</button><span aria-label="to">→</span><button type="button" data-inspect="${step.to}">${html(nodes[step.to].name)}</button></div>
    <section><h3>What crosses this connection</h3><p>${html(step.moves)}</p></section>
    <section><div class="payload-label"><h3>Inside the envelope</h3><span>ILLUSTRATIVE, ABBREVIATED</span></div><pre class="payload">${html(step.payload)}</pre></section>
    <section><h3>What happens here, and why</h3><p class="step-why">${html(step.why)}</p></section>
    <p class="inspect-tip">Click either component name above to explore its other connections.</p>
  </div>`;
  for (const button of $('stepInspector').querySelectorAll('[data-inspect]')) button.onclick = () => inspect(button.dataset.inspect);
}

function renderNode() {
  if (!state.node) return;
  const node = nodes[state.node];
  const ports = connections(state.node);
  const incoming = ports.filter(({step}) => step.to === state.node).length;
  const outgoing = ports.length - incoming;
  $('nodeInspector').innerHTML = `<div class="inspection-content">
    <p class="eyebrow">COMPONENT · ${html(node.sub)}</p><h2>${html(node.name)}</h2>
    <div class="connection-count">${incoming} incoming · ${outgoing} outgoing worked connections</div>
    <p>${html(node.role)}</p><h3>Responsibility</h3><p>${html(node.detail)}</p>
    <h3>What it holds</h3><p>${html(node.holds)}</p>
    <h3>Follow a connection</h3><p class="port-help">Each connection opens a worked path at that exact step.</p>
    <div class="port-filter" role="group" aria-label="Connection direction">${[['all','All'],['in','Incoming'],['out','Outgoing']].map(([id,label]) => `<button type="button" data-filter="${id}" aria-pressed="${state.filter === id}">${label}</button>`).join('')}</div>
    <ul class="port-list">${ports.filter(({step}) => state.filter === 'all' || (state.filter === 'in' ? step.to === state.node : step.from === state.node)).map(({step,path,index,variant}) => {
      const isIn = step.to === state.node;
      return `<li><button type="button" class="${step.kind}" data-jump="${path.id}" data-index="${index}" data-variant="${variant}"><span class="port-direction">${isIn ? 'IN FROM' : 'OUT TO'} ${html(nodes[isIn ? step.from : step.to].name)}</span><strong>${html(step.title)} →</strong><small>${html(path.title)}</small></button></li>`;
    }).join('')}</ul></div>`;
  for (const button of $('nodeInspector').querySelectorAll('[data-filter]')) button.onclick = () => {
    state.filter = button.dataset.filter;
    renderNode();
    $('nodeInspector').querySelector(`[data-filter="${state.filter}"]`).focus({preventScroll:true});
  };
  for (const button of $('nodeInspector').querySelectorAll('[data-jump]')) button.onclick = () => {
    const path = paths.find(p => p.id === button.dataset.jump);
    // A default-path index must never be applied to a different provider variant.
    const provider = button.dataset.variant !== 'default' ? button.dataset.variant : path.variants?.[state.provider] ? 'runsc' : state.provider;
    choose(path,Number(button.dataset.index),provider);
    $('showStep').focus({preventScroll:true});
    revealCurrent();
  };
}

function render() {
  const list = sequence(), step = current(), config = providers[effectiveProvider()];
  for (const button of $('pathCategories').querySelectorAll('button')) button.setAttribute('aria-pressed',String(button.dataset.category === state.path.category));
  $('pathSelect').innerHTML = paths.filter(path => path.category === state.path.category).map(path => `<option value="${path.id}">${escape(path.title)}</option>`).join('');
  $('pathSelect').value = state.path.id;
  $('providerSelect').value = effectiveProvider();
  $('providerSelect').disabled = Boolean(state.path.fixedProvider);
  $('pathIntro').textContent = state.path.intro;
  $('mapHeading').textContent = state.path.question;
  $('copyLink').textContent = 'Copy this view ↗';
  $('providerName').textContent = `${config.provider} · ${config.tier} tier.`;
  $('providerBoundary').textContent = config.boundary;
  $('mapCaption').textContent = state.node ? `Inspecting ${nodes[state.node].name}. Connections are listed in the inspector.` : `${nodes[step.from].name} → ${nodes[step.to].name}`;
  $('stepCounter').textContent = `Connection ${state.index+1} of ${list.length}`;
  $('previous').disabled = state.index === 0;
  $('restart').disabled = state.index === 0 && !state.node && !state.playing;
  $('next').disabled = state.index === list.length - 1;
  $('next').textContent = state.index === list.length-1 ? 'Path complete ✓' : 'Next connection →';
  $('showStep').setAttribute('aria-pressed',String(!state.node));
  $('showNode').setAttribute('aria-pressed',String(Boolean(state.node)));
  $('stepInspector').hidden = Boolean(state.node);
  $('nodeInspector').hidden = !state.node;
  const timelineFocus = document.activeElement?.getAttribute('data-index');
  const oldScroll = $('stepTimeline').scrollLeft;
  $('stepTimeline').innerHTML = list.map((item,index) => `<li><button type="button" class="${item.kind} ${index < state.index ? 'visited' : ''}" data-index="${index}" ${index === state.index ? 'aria-current="step"' : ''}><span class="step-number">${String(index+1).padStart(2,'0')}</span><span>${html(item.title)}</span></button></li>`).join('');
  for (const button of $('stepTimeline').querySelectorAll('button')) button.onclick = () => move(Number(button.dataset.index));
  $('stepTimeline').scrollLeft = oldScroll;
  if (timelineFocus !== null && document.activeElement === document.body) $('stepTimeline').querySelector(`[data-index="${timelineFocus}"]`)?.focus({preventScroll:true});
  renderMap();renderStep();renderNode();
  $('announcement').textContent = `${state.path.title}. Connection ${state.index+1} of ${list.length}: ${step.title}. ${nodes[step.from].name} to ${nodes[step.to].name}.`;
}

function togglePlay() {
  if (state.playing) {stop();render();return;}
  if (state.index === sequence().length-1) state.index = 0;
  state.node = null;
  state.playing = true;
  $('play').textContent = 'Pause';
  $('play').setAttribute('aria-pressed','true');
  save();render();
  const tick = () => {
    if (!state.playing) return;
    if (state.index >= sequence().length-1) {stop();render();return;}
    move(state.index+1,true);
    if (state.index === sequence().length-1) {stop();render();return;}
    // Reading interval, not a simulated latency. Manual stepping has no delay.
    timer = setTimeout(tick,5000);
  };
  timer = setTimeout(tick,5000);
}

$('pathCategories').innerHTML = categories.map((category,index) => `<button type="button" data-category="${category.id}" aria-pressed="false" title="${escape(category.note)}"><span class="category-number">${String(index+1).padStart(2,'0')}</span>${escape(category.name)}</button>`).join('');
for (const button of $('pathCategories').querySelectorAll('button')) button.onclick = () => choose(paths.find(path => path.category === button.dataset.category));
$('pathSelect').onchange = event => choose(paths.find(path => path.id === event.target.value));
$('providerSelect').onchange = event => choose(state.path,0,event.target.value);
$('next').onclick = () => move(state.index+1);
$('previous').onclick = () => move(state.index-1);
$('restart').onclick = () => move(0);
$('play').onclick = togglePlay;
$('showNode').onclick = () => inspect(state.node || current().to);
$('showStep').onclick = () => {state.node = null;save();render();};
$('mapExpand').onclick = () => {
  const expanded = document.querySelector('.workspace').classList.toggle('map-expanded');
  $('mapExpand').textContent = expanded ? 'Restore layout ⤡' : 'Expand map ⤢';
  $('mapExpand').setAttribute('aria-pressed',String(expanded));
};
$('copyLink').onclick = async () => {
  save(true);
  try {
    await navigator.clipboard.writeText(location.href);
    $('copyLink').textContent = 'View link copied ✓';
    $('announcement').textContent = 'Link copied, including path, provider, connection, and selected component.';
  } catch {
    $('copyLink').textContent = 'Copy the browser address';
    $('announcement').textContent = 'Clipboard access was unavailable. The browser address contains this exact view; copy it to share.';
  }
};
document.addEventListener('keydown', event => {
  if (event.ctrlKey || event.metaKey || event.altKey || event.target.closest('input,select,textarea,a,[role="button"],[contenteditable="true"]') || event.target.id === 'mapScroll') return;
  if (event.key === ' ' && event.target.closest('button')) return;
  if (event.key === 'ArrowRight') {event.preventDefault();move(state.index+1);}
  if (event.key === 'ArrowLeft') {event.preventDefault();move(state.index-1);}
  if (event.key === 'Home') {event.preventDefault();move(0);}
  if (event.key === 'End') {event.preventDefault();move(sequence().length-1);}
  if (event.key === ' ') {event.preventDefault();togglePlay();}
});
document.querySelector('.skip-link').onclick = event => {
  event.preventDefault();
  $('walkthrough').focus({preventScroll:true});
  $('walkthrough').scrollIntoView({block:'start'});
};
document.addEventListener('visibilitychange', () => {if (document.hidden) stop();});
window.addEventListener('hashchange', restore);
window.addEventListener('popstate', restore);
reducedMotion.addEventListener('change', () => renderMap());
restore();
