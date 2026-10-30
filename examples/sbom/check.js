/* One receipt checker for the generated page and the offline Node suite. */
(function (root) {
  'use strict';
  const text = new TextEncoder();
  const decode = new TextDecoder('utf-8', {fatal: true});
  const utf8 = value => text.encode(String(value));
  const from64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
  const to64 = value => btoa(Array.from(value, c => String.fromCharCode(c)).join(''));
  const hex = value => Array.from(value, c => c.toString(16).padStart(2, '0')).join('');
  const unhex = value => {
    if (!/^[a-f0-9]{64}$/.test(value)) throw new Error('Expected a lowercase SHA-256 fingerprint');
    return Uint8Array.from(value.match(/../g), c => parseInt(c, 16));
  };
  const concat = parts => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return out;
  };
  const hash = async bytes => hex(new Uint8Array(await root.crypto.subtle.digest('SHA-256', bytes)));
  const compareUTF8 = (a, b) => {
    const x = utf8(a), y = utf8(b);
    for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
    return x.length - y.length;
  };
  async function fileSetDigest(files) {
    const parts = [];
    for (const f of [...files].sort((a, b) => compareUTF8(a.name, b.name))) parts.push(unhex(await hash(utf8(f.name))), unhex(f.hashes[0].content));
    return hash(concat(parts));
  }
  const value = bytes => {
    const size = new Uint8Array(8);
    new DataView(size.buffer).setBigUint64(0, BigInt(bytes.length), false);
    return concat([size, bytes]);
  };
  class Encoder {
    constructor(domain) { this.parts = [value(utf8(domain))]; }
    field(name, content) { this.parts.push(value(utf8(name)), value(content instanceof Uint8Array ? content : utf8(content))); return this; }
    sum() { return hash(concat(this.parts)); }
  }
  function requestDigest(q) {
    // Protocol 1 requests used the first request domain, which had no software rule; the
    // Go record package reads both (record.requestDigest).
    const first = Number(q.protocol) < 2;
    const e = new Encoder(first ? 'plimsoll.run-request.v1' : 'plimsoll.run-request.v2');
    e.field('protocol', q.protocol).field('minimum_isolation', q.minimum_isolation).field('timeout_ms', q.timeout_ms);
    if (!first) {
      const rule = q.software_rule || {mode: '', identities: []};
      e.field('software_mode', rule.mode).field('software_identities', rule.identities.length);
      for (const id of rule.identities) e.field('software_identity', id);
    }
    const p = q.project;
    if (!p) throw new Error('Only project receipts are supported');
    e.field('kind', 'project').field('grant_profile', p.grant_profile).field('files', p.files.length);
    for (const f of p.files) e.field('file_path', f.path).field('file_content', f.content);
    e.field('steps', p.steps.length);
    for (const s of p.steps) e.field('step_command', s);
    e.field('artifacts', p.artifacts.length);
    for (const a of p.artifacts) e.field('artifact_path', a);
    return e.sum();
  }
  const outcomes = ['unspecified', 'completed', 'setup_failed', 'timed_out', 'protocol_error', 'runner_failed'];
  function outcomeNumber(p) {
    if (typeof p.outcome === 'number' && Number.isInteger(p.outcome) && p.outcome >= 0 && p.outcome < outcomes.length) return p.outcome;
    const i = outcomes.indexOf(p.outcome.replace('PROJECT_OUTCOME_', '').toLowerCase());
    if (i < 0) throw new Error('Unknown project outcome');
    return i;
  }
  function resultDigest(a) {
    const p = a.project;
    const e = new Encoder('plimsoll.run-result.v1');
    e.field('kind', 'project').field('outcome', outcomeNumber(p)).field('outcome_detail', p.outcome_detail)
      .field('artifacts_truncated', p.artifacts_truncated).field('steps', p.steps.length);
    for (const s of p.steps) {
      e.field('step_command', s.command).field('step_exit_code', s.exit_code).field('step_timed_out', s.timed_out)
        .field('step_stdout', from64(s.stdout)).field('step_stderr', from64(s.stderr))
        .field('step_stdout_truncated', s.stdout_truncated).field('step_stderr_truncated', s.stderr_truncated);
    }
    e.field('artifacts', p.artifacts.length);
    for (const a of p.artifacts) e.field('artifact_path', a.path).field('artifact_content', from64(a.content));
    return e.sum();
  }
  const recordFields = ['request_sha256', 'result_sha256', 'unanswered', 'provider', 'isolation', 'environment', 'policy',
    'software_identity', 'software_rule_id', 'instance', 'started_unix_ms', 'ended_unix_ms', 'session', 'sequence', 'previous_sha256'];
  const instanceForm = /^[a-z][a-z0-9-]{0,31}:[A-Za-z0-9._:-]{1,127}$/;
  function recordDigest(r) {
    if (r.version !== 4) throw new Error('Only version 4 receipts are supported');
    const e = new Encoder('plimsoll.run-record.v4');
    for (const field of recordFields) e.field(field, r[field] ?? '');
    return e.sum();
  }
  const timestamp = ms => new Date(Number(ms)).toISOString();
  function attachments(bom) {
    const result = {};
    const evidence = bom.declarations.evidence;
    if (evidence.length < 1 || evidence.length > 2 || evidence[0]['bom-ref'] !== 'evidence-run-record') throw new Error('Run evidence missing');
    const take = (item, want) => {
      if (item.data.length !== want.length) throw new Error('Unexpected attachments on ' + item['bom-ref']);
      for (const data of item.data) {
        const a = data.contents.attachment;
        if (result[data.name] || a.encoding !== 'base64' || !want.includes(data.name)) throw new Error('Duplicate or invalid attachment');
        result[data.name] = from64(a.content);
      }
    };
    take(evidence[0], ['envelope.json', 'harness.pub', 'entry.json', 'exchange.json']);
    if (evidence.length === 2) {
      if (evidence[1]['bom-ref'] !== 'evidence-qualification') throw new Error('Qualification evidence missing');
      take(evidence[1], ['statement.json']);
    }
    for (const name of ['envelope.json', 'harness.pub', 'entry.json', 'exchange.json']) if (!result[name]) throw new Error('Missing ' + name);
    return result;
  }
  const pemDER = bytes => from64(decode.decode(bytes).replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/g, ''));
  const pae = (type, body) => concat([utf8('DSSEv1 ' + utf8(type).length + ' ' + type + ' ' + body.length + ' '), body]);
  async function importPublicKey(bom) {
    return root.crypto.subtle.importKey('spki', pemDER(attachments(bom)['harness.pub']), {name: 'Ed25519'}, false, ['verify']);
  }
  const equalHash = (hashes, expected) => hashes?.length === 1 && hashes[0].alg === 'SHA-256' && hashes[0].content === expected;
  function properties(values) {
    const result = {};
    for (const p of values || []) { if (p.name in result) throw new Error('Duplicate property'); result[p.name] = p.value; }
    return result;
  }
  const matchProperties = (values, expected) => {
    const got = properties(values);
    return Object.entries(expected).every(([k, v]) => got['plimsoll:' + k] === String(v));
  };
  // A sealed in-toto statement under the attached key: one signature, this key's id,
  // the given predicate type, and the signature over the DSSE pre-authentication encoding.
  async function sealed(env, key, keyID, predicateType) {
    const body = from64(env.payload), statement = JSON.parse(decode.decode(body)), sig = env.signatures?.[0];
    const ok = env.payloadType === 'application/vnd.in-toto+json' && env.signatures.length === 1 && sig.keyid === keyID
      && statement._type === 'https://in-toto.io/Statement/v1' && statement.predicateType === predicateType
      && statement.subject?.length === 1 && await root.crypto.subtle.verify({name: 'Ed25519'}, key, from64(sig.sig), pae(env.payloadType, body));
    return {ok, statement};
  }
  const ruleNames = {ran_to_the_end: 'ran to the end', kept_the_shapes: "kept the contract's shapes", inventory_is_true: "the inventory is the vendor's",
    one_order_per_command: 'one order per command', right_robot_and_target: 'the right robot and target', ended_as_it_should: 'ended as it should',
    robot_at_target: 'robot at the target', report_is_true: 'the report is true', refused_by_client: 'refused by the client',
    refused_by_broker: 'refused by the broker', no_network: 'no network', no_credential: 'no credential', vendor_saw_nothing: 'the vendor saw nothing'};
  // The verdict claim's words, built the same way the emitter builds them.
  function verdictText(p) {
    let s = `The platform's qualification statement, bound to this run's record, judges ${p.adapter.path} (SHA-256 ${p.adapter.sha256}) in scenario ${p.evidence.scenario.name} (${p.evidence.scenario.says}) by ${p.rules.length} rules read from the vendor's ledger, the vendor's record of its robots and the harness's plan, never from the program's own account:`;
    p.rules.forEach((o, i) => { s += (i ? '; ' : ' ') + (ruleNames[o.rule] || o.rule) + ': ' + (o.held ? 'held' : 'broken') + (o.detail ? ` (${o.detail})` : ''); });
    return s + `. Verdict: ${p.verdict}.`;
  }
  // Each requirement's verdict as the emitter's verifier rebuilds it: held when every rule
  // it names held, not_held naming the ones that did not, not_tested when it names none.
  function requirementsFollow(q, content) {
    try {
      const reqs = JSON.parse(content).requirements, verdicts = q.requirement_verdicts;
      const held = new Map((q.rules || []).map(o => [o.rule, o.held]));
      return Array.isArray(reqs) && Array.isArray(verdicts) && reqs.length === verdicts.length && reqs.every((r, i) => {
        const rules = r.rules || [], v = verdicts[i];
        if (!rules.every(rule => held.has(rule))) return false;
        const failed = rules.filter(rule => !held.get(rule));
        const status = rules.length === 0 ? 'not_tested' : failed.length ? 'not_held' : 'held';
        return v.id === r.id && v.status === status && JSON.stringify(v.rules || []) === JSON.stringify(rules) && JSON.stringify(v.failed || []) === JSON.stringify(failed);
      });
    } catch { return false; }
  }
  async function check(bom, imageFiles = {}) {
    const lines = [];
    const add = (id, label, ok, detail = '') => lines.push({id, label, ok: Boolean(ok), detail});
    try {
      const attached = attachments(bom);
      const x = JSON.parse(decode.decode(attached['exchange.json']));
      const env = JSON.parse(decode.decode(attached['envelope.json']));
      const body = from64(env.payload);
      const statement = JSON.parse(decode.decode(body));
      const r = x.response.record, p = statement.predicate;
      const reqHash = await requestDigest(x.request), resultHash = await resultDigest(x.response);
      const recHash = await recordDigest({...r, request_sha256: reqHash, result_sha256: resultHash});
      add('request', 'Request fingerprint', reqHash === r.request_sha256 && reqHash === p.request_sha256);
      add('result', 'Result fingerprint', resultHash === r.result_sha256 && resultHash === p.result_sha256);
      const subject = statement.subject;
      add('record', 'Record fingerprint and statement subject', recHash === r.record_sha256 && recHash === p.record_sha256
        && subject.length === 1 && subject[0].name === 'run-record' && subject[0].digest.sha256 === recHash);
      const fields = ['version', ...recordFields, 'record_sha256'];
      const rule = x.request.software_rule;
      let ruleID = '';
      if (rule?.mode) ruleID = rule.identities.length === 1 ? 'exact:' + rule.identities[0]
        : 'approved:sha256:' + await hash(utf8([...rule.identities].sort().join('\x00')));
      const tiers = ['', 'process', 'container', 'kernel', 'vm'];
      add('fields', 'Signed fields match the attached exchange', fields.every(k => String(p[k] ?? '') === String(r[k] ?? ''))
        && r.provider === x.response.sandbox && r.isolation === x.response.isolation && r.environment === x.response.environment
        && r.software_identity === x.response.software_identity && r.software_rule_id === ruleID
        && (r.instance ?? '') === (x.response.instance ?? '') && (!r.instance || instanceForm.test(r.instance))
        && (!rule?.mode || rule.identities.includes(r.software_identity))
        && tiers.indexOf(r.isolation) >= Math.max(1, tiers.indexOf(x.request.minimum_isolation))
        && (!x.request.minimum_isolation || tiers.includes(x.request.minimum_isolation))
        && r.session === '' && String(r.sequence) === '0' && r.previous_sha256 === '' && !r.unanswered && !p.unanswered);
      const der = pemDER(attached['harness.pub']), keyID = await hash(der);
      const key = await importPublicKey(bom);
      const record = await sealed(env, key, keyID, 'https://plimsollmark.github.io/plimsoll/run-record/v1');
      add('seal', 'Ed25519 seal on the signed statement', record.ok);
      const program = bom.metadata.component, files = [...program.components].sort((a, b) => compareUTF8(a.name, b.name));
      const stored = x.request.project.files;
      let fileOK = files.length === stored.length && new Set(files.map(f => f.name)).size === files.length;
      for (const f of files) {
        const source = stored.find(s => s.path === f.name);
        fileOK = fileOK && f.type === 'file' && !!source && equalHash(f.hashes, await hash(utf8(source.content)))
          && matchProperties(f.properties, {bytes: utf8(source.content).length});
      }
      add('files', 'Each file fingerprint matches its attached content', fileOK);
      const fileHash = await fileSetDigest(files);
      add('file-set', 'Program file-set fingerprint', equalHash(program.hashes, fileHash) && program.version === fileHash.slice(0, 12));
      const selected = /^oci-manifest:[a-z0-9._/-]+@sha256:([a-f0-9]{64})$/.exec(r.software_identity);
      const booted = !r.software_identity && /^dockercloud-image:sha256:([a-f0-9]{64})$/.exec(r.environment);
      const imageHash = selected ? selected[1] : booted ? booted[1] : '';
      const image = bom.components[0];
      const w = bom.formulation[0].workflows[0];
      const grant = x.request.project.grant_profile;
      const ps = matchProperties(program.properties, {request_sha256: reqHash, result_sha256: resultHash, record_sha256: recHash})
        && matchProperties(w.outputs[0].properties, {result_sha256: resultHash})
        && matchProperties(image.properties, {environment: r.environment, software_identity: r.software_identity})
        && imageHash && image.version === 'sha256:' + imageHash && equalHash(image.hashes, imageHash)
        && w.uid === recHash && w.timeStart === timestamp(r.started_unix_ms) && w.timeEnd === timestamp(r.ended_unix_ms)
        && matchProperties(w.properties, {provider: r.provider, isolation: r.isolation, minimum_isolation: x.request.minimum_isolation,
          timeout_ms: x.request.timeout_ms, grant: grant || 'none', outcome: outcomes[outcomeNumber(x.response.project)]})
        && (!r.policy || matchProperties(w.properties, {policy: r.policy}));
      add('properties', 'BOM fingerprints and run properties', ps);
      const imageClaim = selected
        ? `The daemon states that the run executed in the image whose OCI manifest digest is sha256:${imageHash} (environment ${r.environment}), verified before launch.`
        : `The daemon states that the run executed in a Docker Cloud microVM booted from the image whose linux/amd64 manifest digest is sha256:${imageHash} (environment ${r.environment}), the provider's pin, which it compares with the digest the cloud reports each sandbox booted and refuses to run on a difference.`;
      const tierTail = grant
        ? `the stored request names host-API grant profile ${grant}, the run's only route out, served by the daemon's broker, and the result digest is ${resultHash}. Network beyond the grant is provider configuration; this record is not a network measurement.`
        : `the stored request names no host-API grant and the result digest is ${resultHash}. The provider's no-grant configuration supplies network isolation; this record is not a network measurement.`;
      const expectedClaims = [
        `The program's ${files.length} files, file-set digest ${fileHash}, are the files in the stored request whose signed digest ${reqHash} covers them with the isolation floor and timeout.`,
        imageClaim,
        `The daemon states provider ${r.provider} and isolation tier ${r.isolation}, at or above requested floor ${x.request.minimum_isolation}, from ${timestamp(r.started_unix_ms)} to ${timestamp(r.ended_unix_ms)} UTC; ` + tierTail
      ];
      const qualified = Boolean(attached['statement.json']);
      add('claims', 'Every claim fingerprint matches the receipt', bom.declarations.claims.length === (qualified ? 4 : 3)
        && expectedClaims.every((want, i) => { const c = bom.declarations.claims[i]; return c['bom-ref'] === 'claim-' + ['code', 'image', 'tier'][i]
          && c.predicate === want && c.target === 'program' && c.evidence.length === 1 && c.evidence[0] === 'evidence-run-record'; }));
      // The attached bundle line: its link is the harness's seal over the line's content
      // (the line without its last member, the link) at the index the BOM states.
      const lineBytes = attached['entry.json'], entry = JSON.parse(decode.decode(lineBytes));
      const marker = utf8(',"link":');
      let cut = -1;
      outer: for (let i = lineBytes.length - marker.length; i >= 0; i--) {
        for (let j = 0; j < marker.length; j++) if (lineBytes[i + j] !== marker[j]) continue outer;
        cut = i; break;
      }
      const bomProps = properties(bom.properties);
      const link = entry.link ? await sealed(entry.link, key, keyID, 'https://plimsollmark.github.io/plimsoll/bundle-link/v1') : {ok: false, statement: {subject: [{}], predicate: {}}};
      const place = link.statement.predicate;
      const refs = program.externalReferences.filter(ref => ref.type === 'attestation' && ref.url.endsWith('bundle.jsonl'));
      add('line', 'Bundle line sealed at its stated place; the whole bundle is referenced by fingerprint', cut > 0 && link.ok
        && link.statement.subject[0].name === 'bundle-line' && link.statement.subject[0].digest.sha256 === place.entry_sha256
        && !place.checkpoint && place.entry_sha256 === await hash(concat([lineBytes.slice(0, cut), utf8('}')]))
        && String(place.index) === bomProps['plimsoll:bundle_line']
        && entry.envelope.payload === env.payload && entry.envelope.signatures.length === 1 && entry.envelope.signatures[0].sig === env.signatures[0].sig
        && refs.length === 1 && equalHash(refs[0].hashes, bomProps['plimsoll:bundle_sha256']));
      if (qualified) {
        const st = JSON.parse(decode.decode(attached['statement.json']));
        const verdict = await sealed(st, key, keyID, 'https://plimsollmark.github.io/plimsoll/examples/adapter/qualification/v2');
        const q = verdict.statement.predicate || {};
        add('statement', "Referee's statement sealed under the same key and bound to this record", verdict.ok
          && verdict.statement.subject[0].name === 'run-record' && verdict.statement.subject[0].digest.sha256 === recHash
          && String(q.run) === bomProps['plimsoll:bundle_line']);
        const judged = stored.find(f => f.path === q.adapter?.path), harness = stored.find(f => f.path === 'harness.js');
        const pinned = q.requirements ? stored.filter(f => f.path === q.requirements.path) : [];
        const judgedOK = judged && await hash(utf8(judged.content)) === q.adapter.sha256
          && (q.evidence?.kind !== 'adapter' || (harness && await hash(utf8(harness.content)) === q.harness_sha256
            && pinned.length === 1 && await hash(utf8(pinned[0].content)) === q.requirements.sha256 && requirementsFollow(q, pinned[0].content)))
          && (q.evidence?.kind === 'adapter' || (q.requirements == null && q.requirement_verdicts == null));
        const held = Array.isArray(q.rules) && q.rules.length > 0 && q.rules.every(o => o.held);
        const claim = bom.declarations.claims[3], map = bom.declarations.attestations[0].map[3];
        const qrefs = program.externalReferences.filter(ref => ref.type === 'attestation' && ref.url.endsWith('qualification.jsonl'));
        add('verdict', 'Verdict claim and conformance score say what the sealed statement says; the judged files, the pinned requirements file included, are the stored ones, and each requirement verdict follows from the rules', judgedOK
          && (q.verdict === 'pass') === held && (q.verdict === 'pass' || q.verdict === 'fail')
          && claim?.['bom-ref'] === 'claim-verdict' && claim.target === 'program' && claim.predicate === verdictText(q)
          && claim.evidence.length === 2 && claim.evidence[0] === 'evidence-qualification' && claim.evidence[1] === 'evidence-run-record'
          && map?.requirement === 'req-verdict' && map.conformance.score === (held ? 1 : 0)
          && qrefs.length === 1 && equalHash(qrefs[0].hashes, bomProps['plimsoll:qualification_sha256']));
      }
      if (image.externalReferences?.length) {
        const name = 'image-' + imageHash.slice(0, 12) + '.cdx.json';
        const bytes = from64(imageFiles[name] || '');
        const label = JSON.parse(decode.decode(bytes));
        const references = image.externalReferences;
        const pages = program.externalReferences.find(ref => ref.type === 'documentation').url.replace(/index\.html$/, '');
        add('image', 'Image label fingerprint, manifest and BOM-Link', references.length === 2
          && references.every(ref => ref.type === 'bom') && references[0].url === pages + name
          && equalHash(references[0].hashes, await hash(bytes)) && label.metadata.component.version === image.version
          && references[1].url === 'urn:cdx:' + label.serialNumber.replace('urn:uuid:', '') + '/' + label.version + '#' + encodeURIComponent(label.metadata.component['bom-ref']));
      }
    } catch (err) { add('input', 'Receipt can be read and checked', false, err.message); }
    return lines;
  }
  function changeOneCharacter(bom) {
    const changed = structuredClone(bom);
    const a = changed.declarations.evidence[0].data.find(d => d.name === 'envelope.json').contents.attachment;
    const env = JSON.parse(decode.decode(from64(a.content)));
    const bytes = from64(env.payload), statement = JSON.parse(decode.decode(bytes));
    const subject = statement.subject[0].digest.sha256;
    const needle = utf8(JSON.stringify(subject));
    let at = -1;
    outer: for (let i = 0; i <= bytes.length - needle.length; i++) {
      for (let j = 0; j < needle.length; j++) if (bytes[i + j] !== needle[j]) continue outer;
      at = i + 1; break;
    }
    if (at < 0) throw new Error('Subject fingerprint byte not found');
    const before = String.fromCharCode(bytes[at]);
    bytes[at] = before === '0' ? 49 : 48;
    env.payload = to64(bytes);
    a.content = to64(utf8(JSON.stringify(env)));
    return {bom: changed, offset: at, before, after: String.fromCharCode(bytes[at])};
  }
  root.PlimsollReceipt = {check, changeOneCharacter, importPublicKey, requestDigest, resultDigest, recordDigest, fileSetDigest};
})(globalThis);
