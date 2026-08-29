/**
 * run-tests.js
 *
 * Executes the IBM Verify Identity Access mapping rules against the local
 * runtime shim and asserts their behaviour.
 *
 *   node test/run-tests.js
 *
 * The rule sources under rules/ are the artefacts that would be uploaded
 * to the appliance, unmodified. This harness supplies the same global
 * objects the appliance supplies, so what is tested here is the rule
 * logic itself — not a reimplementation of it.
 */

'use strict';

const path = require('path');
const {
  Attribute,
  STSUniversalUser,
  Scope,
  InfoMapContext,
  SuccessFlag,
  MacroMap,
  PageSelector,
  UserLookupHelper,
  IDMappingExtUtils,
  runRule,
} = require('./ivia-shim');

const RULES = path.join(__dirname, '..', 'rules');

// ---------------------------------------------------------------------
// Minimal test framework
// ---------------------------------------------------------------------

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  IDMappingExtUtils.clearTrace();
  try {
    fn();
    passed++;
    console.log('  PASS  ' + name);
  } catch (err) {
    failed++;
    failures.push({ name, err });
    console.log('  FAIL  ' + name);
    console.log('        ' + err.message);
  }
}

function eq(actual, expected, what) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) {
    throw new Error((what || 'value') + ': expected ' + e + ', got ' + a);
  }
}

function isTrue(v, what) {
  if (v !== true) throw new Error((what || 'value') + ': expected true, got ' + JSON.stringify(v));
}

function isFalse(v, what) {
  if (v !== false) throw new Error((what || 'value') + ': expected false, got ' + JSON.stringify(v));
}

function absent(obj, key) {
  if (Object.prototype.hasOwnProperty.call(obj, key)) {
    throw new Error('claim "' + key + '" should not have been released, got ' + JSON.stringify(obj[key]));
  }
}

function section(title) {
  console.log('\n' + title);
  console.log('-'.repeat(title.length));
}

// ---------------------------------------------------------------------
// Helpers to build a token-mapping invocation
// ---------------------------------------------------------------------

const AM = 'urn:ibm:names:ITFIM:5.1:accessmanager';

function stsuuWith(principal, attrs) {
  const u = new STSUniversalUser(principal);
  Object.keys(attrs || {}).forEach(name => {
    u.addAttribute(new Attribute(name, AM, attrs[name]));
  });
  return u;
}

function runTokenRule(file, stsuu) {
  const tokenData = {};
  const idtokenData = {};
  runRule(path.join(RULES, file), { stsuu, tokenData, idtokenData });
  return { tokenData, idtokenData, stsuu };
}

// =====================================================================
section('oidc-idtoken-claims.js  —  controlled claim release');
// =====================================================================

test('sets sub from the STSUU principal', () => {
  const { idtokenData } = runTokenRule('oidc-idtoken-claims.js',
    stsuuWith('6440079YE3', {}));
  eq(idtokenData.sub, '6440079YE3', 'sub');
});

test('releases mapped single-valued attributes', () => {
  const { idtokenData } = runTokenRule('oidc-idtoken-claims.js',
    stsuuWith('mobileye', { department: 'Identity Platform', title: 'Engineer' }));
  eq(idtokenData.department, 'Identity Platform', 'department');
  eq(idtokenData.job_title, 'Engineer', 'job_title');
});

test('releases multi-valued groups as an array under groupIds', () => {
  const { idtokenData } = runTokenRule('oidc-idtoken-claims.js',
    stsuuWith('mobileye', { groups: ['admin', 'Lab-Admins'] }));
  eq(idtokenData.groupIds, ['admin', 'Lab-Admins'], 'groupIds');
});

test('does NOT release an attribute that is absent', () => {
  const { idtokenData } = runTokenRule('oidc-idtoken-claims.js',
    stsuuWith('mobileye', { department: 'Finance' }));
  absent(idtokenData, 'labClearance');
  absent(idtokenData, 'job_title');
});

test('does NOT release an attribute present but empty', () => {
  const { idtokenData } = runTokenRule('oidc-idtoken-claims.js',
    stsuuWith('mobileye', { department: '' }));
  absent(idtokenData, 'department');
});

test('does NOT release an unmapped attribute (data minimisation)', () => {
  const { idtokenData } = runTokenRule('oidc-idtoken-claims.js',
    stsuuWith('mobileye', { homePostalAddress: '1 Example Street', mobile: '555-0100' }));
  absent(idtokenData, 'homePostalAddress');
  absent(idtokenData, 'mobile');
});

test('emits nothing when there is no principal', () => {
  const { idtokenData } = runTokenRule('oidc-idtoken-claims.js',
    stsuuWith(null, { department: 'Finance' }));
  eq(Object.keys(idtokenData).length, 0, 'claim count');
});

// =====================================================================
section('oidc-pretoken-derived.js  —  derived clearance and downscoping');
// =====================================================================

test('explicit labClearance attribute takes precedence over groups', () => {
  const { tokenData } = runTokenRule('oidc-pretoken-derived.js',
    stsuuWith('mobileye', {
      labClearance: 'elevated',
      groups: ['Lab-Admins'],
      authenticationMethods: ['totp'],
    }));
  eq(tokenData.clearance, 'elevated', 'clearance');
});

test('derives high clearance from Lab-Admins membership', () => {
  const { tokenData } = runTokenRule('oidc-pretoken-derived.js',
    stsuuWith('mobileye', {
      groups: ['Lab-Admins'],
      authenticationMethods: ['totp', '2fa'],
    }));
  eq(tokenData.clearance, 'high', 'clearance');
});

test('applies group precedence: Lab-Admins outranks Lab-Engineering', () => {
  const { tokenData } = runTokenRule('oidc-pretoken-derived.js',
    stsuuWith('mobileye', {
      groups: ['Lab-Engineering', 'Lab-Admins'],
      authenticationMethods: ['totp'],
    }));
  eq(tokenData.clearance, 'high', 'clearance');
});

test('defaults to standard when no group matches (fail closed)', () => {
  const { tokenData } = runTokenRule('oidc-pretoken-derived.js',
    stsuuWith('someone', { groups: ['everyone'], authenticationMethods: ['totp'] }));
  eq(tokenData.clearance, 'standard', 'clearance');
});

test('DOWNSCOPES high to standard when no second factor was used', () => {
  const { tokenData } = runTokenRule('oidc-pretoken-derived.js',
    stsuuWith('mobileye', { groups: ['Lab-Admins'], authenticationMethods: ['password'] }));
  eq(tokenData.clearance, 'standard', 'clearance');
  isFalse(tokenData.mfa, 'mfa');
});

test('DOWNSCOPES high to standard when no methods are recorded at all', () => {
  const { tokenData } = runTokenRule('oidc-pretoken-derived.js',
    stsuuWith('mobileye', { groups: ['Lab-Admins'] }));
  eq(tokenData.clearance, 'standard', 'clearance');
});

test('retains high clearance when a second factor was used', () => {
  const { tokenData } = runTokenRule('oidc-pretoken-derived.js',
    stsuuWith('mobileye', { groups: ['Lab-Admins'], authenticationMethods: ['password', 'totp'] }));
  eq(tokenData.clearance, 'high', 'clearance');
  isTrue(tokenData.mfa, 'mfa');
});

test('records the downscope decision in the trace for audit', () => {
  runTokenRule('oidc-pretoken-derived.js',
    stsuuWith('mobileye', { groups: ['Lab-Admins'], authenticationMethods: ['password'] }));
  const trace = IDMappingExtUtils.getTrace().join('\n');
  if (trace.indexOf('downscoping') === -1) {
    throw new Error('expected a downscope entry in the trace, got:\n' + trace);
  }
});

test('writes derivedClearance back onto the STSUU for later chain modules', () => {
  const { stsuu } = runTokenRule('oidc-pretoken-derived.js',
    stsuuWith('mobileye', { groups: ['Lab-Admins'], authenticationMethods: ['totp'] }));
  eq(stsuu.getAttributeContainer().getAttributeValueByName('derivedClearance'),
     'high', 'derivedClearance on STSUU');
});

test('mirrors clearance onto the id_token as well as the access token', () => {
  const { tokenData, idtokenData } = runTokenRule('oidc-pretoken-derived.js',
    stsuuWith('mobileye', { groups: ['Lab-Admins'], authenticationMethods: ['totp'] }));
  eq(idtokenData.clearance, tokenData.clearance, 'id_token clearance');
});

// =====================================================================
section('infomap-stepup-clearance.js  —  custom authentication module');
// =====================================================================

const PARAM_NS   = 'urn:ibm:security:asf:request:parameter';
const SESSION_NS = 'urn:ibm:security:asf:response:token:attributes';

UserLookupHelper.loadDirectory({
  'mobileye': {
    id: 'mobileye',
    password: 'correct-horse',
    attributes: { mail: 'matthew@example.com', labClearance: 'high' },
  },
  'labuser1': {
    id: 'labuser1',
    password: 'lab-pass',
    attributes: { mail: 'lab@example.com', labClearance: 'standard' },
  },
  'dup-a': { id: 'dup-a', password: 'x', attributes: { mail: 'shared@example.com' } },
  'dup-b': { id: 'dup-b', password: 'x', attributes: { mail: 'shared@example.com' } },
});

function runInfoMap(requestParams, sessionAttrs) {
  const request = {}; request[PARAM_NS] = requestParams || {};
  const session = {}; session[SESSION_NS] = sessionAttrs || {};

  const context = new InfoMapContext(request, session);
  const success = new SuccessFlag();
  const macros  = new MacroMap();
  const page    = new PageSelector();

  runRule(path.join(RULES, 'infomap-stepup-clearance.js'),
          { context, success, macros, page });

  return { success, macros, page, session: context.dumpSession()[SESSION_NS] };
}

test('renders the login page when no credentials are submitted', () => {
  const r = runInfoMap({}, {});
  isFalse(r.success.getValue(), 'success');
  eq(r.page.getValue(), '/authsvc/authenticator/lab/clearance_login.html', 'page');
});

test('rejects an unknown user with a generic error', () => {
  const r = runInfoMap({ username: 'nobody', password: 'whatever' }, {});
  isFalse(r.success.getValue(), 'success');
  eq(r.macros.get('@ERROR_MESSAGE@'), 'Username or password is incorrect.', 'error');
});

test('rejects a wrong password with the SAME generic error (no user enumeration)', () => {
  const unknown = runInfoMap({ username: 'nobody',   password: 'x' }, {});
  const wrongPw = runInfoMap({ username: 'mobileye', password: 'wrong' }, {});
  isFalse(wrongPw.success.getValue(), 'success');
  eq(wrongPw.macros.get('@ERROR_MESSAGE@'),
     unknown.macros.get('@ERROR_MESSAGE@'),
     'error strings must be identical');
});

test('authenticates a valid user', () => {
  const r = runInfoMap({ username: 'labuser1', password: 'lab-pass' }, {});
  isTrue(r.success.getValue(), 'success');
  eq(r.session.username, 'labuser1', 'session username');
});

test('DOWNSCOPES high clearance when the session has no second factor', () => {
  const r = runInfoMap({ username: 'mobileye', password: 'correct-horse' }, {});
  isTrue(r.success.getValue(), 'success');
  eq(r.session.labClearance, 'standard', 'clearance');
  eq(r.session.clearanceDownscoped, 'true', 'downscope marker');
});

test('retains high clearance when the session carries a second factor', () => {
  const r = runInfoMap(
    { username: 'mobileye', password: 'correct-horse' },
    { authenticationMethods: 'password,totp' });
  isTrue(r.success.getValue(), 'success');
  eq(r.session.labClearance, 'high', 'clearance');
});

test('resolves a unique email alias to the account', () => {
  const r = runInfoMap({ username: 'lab@example.com', password: 'lab-pass' }, {});
  isTrue(r.success.getValue(), 'success');
  eq(r.session.username, 'labuser1', 'resolved id');
});

test('REFUSES an ambiguous email alias rather than guessing', () => {
  const r = runInfoMap({ username: 'shared@example.com', password: 'x' }, {});
  isFalse(r.success.getValue(), 'success');
  eq(r.macros.get('@ERROR_MESSAGE@'), 'Username or password is incorrect.', 'error');
});

test('never sets success true on any failure path', () => {
  [
    {},
    { username: 'mobileye' },
    { password: 'correct-horse' },
    { username: 'nobody', password: 'x' },
    { username: 'mobileye', password: 'wrong' },
    { username: 'shared@example.com', password: 'x' },
  ].forEach((params, i) => {
    const r = runInfoMap(params, {});
    if (r.success.getValue() === true) {
      throw new Error('failure path ' + i + ' authenticated the request');
    }
  });
});

// =====================================================================

console.log('\n' + '='.repeat(60));
console.log('  ' + passed + ' passed, ' + failed + ' failed');
console.log('='.repeat(60));

if (failed > 0) {
  failures.forEach(f => console.log('\n' + f.name + '\n  ' + f.err.stack));
  process.exit(1);
}
