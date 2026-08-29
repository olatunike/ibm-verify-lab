/**
 * ivia-shim.js
 *
 * A local implementation of the IBM Verify Identity Access JavaScript
 * mapping-rule runtime, sufficient to execute and unit-test mapping
 * rules on a laptop without an appliance or container.
 *
 * On the appliance, mapping rules run inside a Rhino/Nashorn engine with
 * a set of GLOBAL objects already in scope — there is no `require`, no
 * `module.exports`. This shim reproduces that: rules are executed with
 * Node's `vm` module against a context carrying the same globals, so the
 * rule source here is byte-identical to what would be uploaded to the
 * appliance.
 *
 * Object surface implemented (from IBM's JavaScript mapping rule
 * reference and the InfoMap authentication mechanism API):
 *
 *   STS / token mapping rules
 *     stsuu               STSUniversalUser
 *     Attribute           constructor
 *     tokenData           claims for the access token
 *     idtokenData         claims for the id_token / userinfo
 *     IDMappingExtUtils   traceString()
 *
 *   InfoMap authentication mechanism
 *     context / Scope     request and session data
 *     success             authentication outcome
 *     macros              values injected into the login template
 *     page                template selection
 *     UserLookupHelper    registry lookup
 *
 * NOT a reimplementation of the product. It is a test double with the
 * same contract, so rule LOGIC can be verified before deployment.
 */

'use strict';

const vm = require('vm');
const fs = require('fs');

// ---------------------------------------------------------------------
// Attribute
// ---------------------------------------------------------------------

class Attribute {
  constructor(name, type, value) {
    this._name = name;
    this._type = type;
    this._values = Array.isArray(value) ? value.slice() : [value];
  }
  getName() { return this._name; }
  getType() { return this._type; }
  getValue() { return this._values[0]; }
  getValues() { return this._values.slice(); }
}

// ---------------------------------------------------------------------
// AttributeContainer
// ---------------------------------------------------------------------

class AttributeContainer {
  constructor() { this._attrs = []; }

  getAttributeByName(name) {
    return this._attrs.find(a => a.getName() === name) || null;
  }
  getAttributeValueByName(name) {
    const a = this.getAttributeByName(name);
    return a ? a.getValue() : null;
  }
  getAttributeValuesByName(name) {
    const a = this.getAttributeByName(name);
    return a ? a.getValues() : [];
  }
  setAttribute(nameOrAttr, type, values) {
    if (nameOrAttr instanceof Attribute) {
      this.removeAttributeByNameAndType(nameOrAttr.getName(), nameOrAttr.getType());
      this._attrs.push(nameOrAttr);
      return;
    }
    this.removeAttributeByNameAndType(nameOrAttr, type);
    this._attrs.push(new Attribute(nameOrAttr, type, values));
  }
  removeAttributeByNameAndType(name, type) {
    this._attrs = this._attrs.filter(
      a => !(a.getName() === name && a.getType() === type)
    );
  }
  listAttributes() { return this._attrs.slice(); }
}

// ---------------------------------------------------------------------
// STSUniversalUser
// ---------------------------------------------------------------------

class STSUniversalUser {
  constructor(principalName) {
    this._principal = principalName || null;
    this._attributes = new AttributeContainer();   // AttributeList
    this._contextAttrs = new AttributeContainer(); // ContextAttributes
  }

  getPrincipalName() { return this._principal; }
  setPrincipalName(n) { this._principal = n; }

  getAttributeContainer() { return this._attributes; }
  getContextAttributes() { return this._contextAttrs; }

  addAttribute(attr) { this._attributes.setAttribute(attr); }
  addContextAttribute(attr) { this._contextAttrs.setAttribute(attr); }

  getAttributeValueByName(name) {
    return this._attributes.getAttributeValueByName(name);
  }

  toString() {
    const dump = c => c.listAttributes().reduce((o, a) => {
      o[a.getName()] = a.getValues();
      return o;
    }, {});
    return JSON.stringify({
      principal: this._principal,
      attributes: dump(this._attributes),
      context: dump(this._contextAttrs),
    }, null, 2);
  }

  /** Build an STSUU from the stsuujson shape IBM's runjs utility accepts. */
  static fromRunjsJson(json) {
    const u = new STSUniversalUser(
      json.principal && json.principal.name ? json.principal.name : null
    );
    (json.attributes || []).forEach(a =>
      u.addAttribute(new Attribute(a.name, a.type || 'urn:ibm:names:ITFIM:5.1:accessmanager', a.value))
    );
    (json.context || []).forEach(a =>
      u.addContextAttribute(new Attribute(a.name, a.type || 'urn:ibm:names:ITFIM:5.1:accessmanager', a.value))
    );
    return u;
  }
}

// ---------------------------------------------------------------------
// InfoMap runtime objects
// ---------------------------------------------------------------------

const Scope = Object.freeze({ REQUEST: 'request', SESSION: 'session' });

class InfoMapContext {
  constructor(request = {}, session = {}) {
    this._request = request;
    this._session = session;
  }
  /** context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "username") */
  get(scope, namespace, key) {
    const store = scope === Scope.REQUEST ? this._request : this._session;
    const ns = store[namespace];
    if (!ns) return null;
    return key in ns ? ns[key] : null;
  }
  set(scope, namespace, key, value) {
    const store = scope === Scope.REQUEST ? this._request : this._session;
    if (!store[namespace]) store[namespace] = {};
    store[namespace][key] = value;
  }
  dumpSession() { return JSON.parse(JSON.stringify(this._session)); }
}

class SuccessFlag {
  constructor() { this._value = null; }
  setValue(v) { this._value = !!v; }
  setResult(v) { this._value = !!v; }   // some releases expose setResult
  getValue() { return this._value; }
}

class MacroMap {
  constructor() { this._m = {}; }
  put(k, v) { this._m[k] = v; }
  get(k) { return this._m[k]; }
  all() { return Object.assign({}, this._m); }
}

class PageSelector {
  constructor() { this._page = null; }
  setValue(p) { this._page = p; }
  getValue() { return this._page; }
}

// ---------------------------------------------------------------------
// Registry lookup double
// ---------------------------------------------------------------------

class FakeUser {
  constructor(record) { this._r = record; }
  getId() { return this._r.id; }
  getAttribute(name) { return this._r.attributes[name] || null; }
  authenticate(password) { return password === this._r.password; }
}

class UserLookupHelper {
  constructor() { this._ready = false; }
  init() { this._ready = true; return true; }

  getUser(id) {
    const rec = UserLookupHelper._directory[id];
    return rec ? new FakeUser(rec) : null;
  }
  search(attrName, value) {
    return Object.keys(UserLookupHelper._directory).filter(
      id => UserLookupHelper._directory[id].attributes[attrName] === value
    );
  }
  getUserByNativeId(id) { return this.getUser(id); }

  static loadDirectory(dir) { UserLookupHelper._directory = dir; }
}
UserLookupHelper._directory = {};

const IDMappingExtUtils = {
  _trace: [],
  traceString(s) { IDMappingExtUtils._trace.push(String(s)); },
  getTrace() { return IDMappingExtUtils._trace.slice(); },
  clearTrace() { IDMappingExtUtils._trace = []; },
};

// ---------------------------------------------------------------------
// Rule execution
// ---------------------------------------------------------------------

/**
 * Execute a mapping rule file against a set of globals, exactly as the
 * appliance would: the source runs with those names already in scope.
 *
 * `importPackage` / `importClass` are no-ops here — on the appliance they
 * pull Java classes into scope; the shim supplies equivalents directly.
 */
function runRule(rulePath, globals) {
  const source = fs.readFileSync(rulePath, 'utf8');

  // `Packages.com.tivoli.am.fim...` is an arbitrarily deep Java namespace
  // on the appliance. A self-returning proxy lets any depth resolve, so
  // importPackage/importClass lines run unchanged.
  const javaNamespace = new Proxy(function () {}, {
    get: () => javaNamespace,
    apply: () => javaNamespace,
    construct: () => javaNamespace,
  });

  const sandbox = Object.assign({
    Attribute,
    Scope,
    IDMappingExtUtils,
    UserLookupHelper,
    importPackage: () => {},
    importClass: () => {},
    Packages: javaNamespace,
    java: javaNamespace,
    print: () => {},
    console,
    JSON,
  }, globals);

  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, { filename: rulePath });
  return sandbox;
}

module.exports = {
  Attribute,
  AttributeContainer,
  STSUniversalUser,
  Scope,
  InfoMapContext,
  SuccessFlag,
  MacroMap,
  PageSelector,
  UserLookupHelper,
  IDMappingExtUtils,
  runRule,
};
