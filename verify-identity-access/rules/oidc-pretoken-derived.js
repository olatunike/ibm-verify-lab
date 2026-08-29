/**
 * oidc-pretoken-derived.js
 *
 * IBM Verify Identity Access — OAuth/OIDC pre-token mapping rule.
 * Deploy: AAC > Global Settings > Mapping Rules, category "OAUTH".
 *
 * PURPOSE
 * -------
 * Derive an authorization claim that does not exist as a stored
 * attribute, and downscope the access token when the request context
 * does not warrant full privilege.
 *
 * WHY THIS RULE EXISTS
 * --------------------
 * A declarative attribute-mapping table can only release attributes that
 * are already stored on the user. It cannot:
 *
 *   - compute a value from several inputs
 *   - apply precedence between conflicting sources
 *   - vary the result by network, client, or authentication strength
 *   - refuse to emit a privileged claim under weak authentication
 *
 * All four are ordinary requirements. They are the reason a mapping rule
 * is written rather than a table filled in.
 *
 * CLEARANCE PRECEDENCE
 * --------------------
 *   1. An explicit labClearance attribute on the user always wins.
 *   2. Otherwise clearance is derived from group membership.
 *   3. Otherwise it defaults to "standard" — never to a privileged value.
 *
 * DOWNSCOPING
 * -----------
 * "high" is emitted only when the authentication carried a second factor.
 * A privileged claim minted off a single factor is a privilege-escalation
 * path: anyone who phishes the password inherits the elevated claim.
 * Here the claim degrades to "standard" instead, and the reason is
 * recorded in the trace for audit.
 */

importPackage(Packages.com.tivoli.am.fim.trustserver.sts);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.uuser);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

var TRACE = 'oidc-pretoken-derived: ';

// Group -> clearance. Ordered most privileged first; first match wins.
var GROUP_CLEARANCE = [
  { group: 'Lab-Admins',    clearance: 'high'     },
  { group: 'Lab-Engineering', clearance: 'elevated' },
];

var DEFAULT_CLEARANCE = 'standard';

// Authentication methods that count as a second factor.
var SECOND_FACTORS = ['totp', '2fa', 'fido2', 'otp', 'mfa'];

function hasSecondFactor(methods) {
  if (methods === null) return false;
  for (var i = 0; i < methods.length; i++) {
    for (var j = 0; j < SECOND_FACTORS.length; j++) {
      if (String(methods[i]).toLowerCase() === SECOND_FACTORS[j]) return true;
    }
  }
  return false;
}

function deriveClearance(attrs) {
  // 1. Explicit attribute wins.
  var explicit = attrs.getAttributeValueByName('labClearance');
  if (explicit !== null && String(explicit).length > 0) {
    return { value: String(explicit), source: 'attribute' };
  }

  // 2. Derive from group membership, highest privilege first.
  var groups = attrs.getAttributeValuesByName('groups');
  if (groups !== null) {
    for (var i = 0; i < GROUP_CLEARANCE.length; i++) {
      for (var j = 0; j < groups.length; j++) {
        if (String(groups[j]) === GROUP_CLEARANCE[i].group) {
          return { value: GROUP_CLEARANCE[i].clearance, source: 'group:' + groups[j] };
        }
      }
    }
  }

  // 3. Fail closed.
  return { value: DEFAULT_CLEARANCE, source: 'default' };
}

(function () {

  var principal = stsuu.getPrincipalName();
  if (principal === null) {
    IDMappingExtUtils.traceString(TRACE + 'no principal; refusing to mint claims');
    return;
  }

  var attrs = stsuu.getAttributeContainer();

  var derived = deriveClearance(attrs);
  var clearance = derived.value;

  // Downscope: a privileged clearance requires a second factor.
  var methods = attrs.getAttributeValuesByName('authenticationMethods');
  var mfa = hasSecondFactor(methods);

  if (clearance === 'high' && !mfa) {
    IDMappingExtUtils.traceString(
      TRACE + 'downscoping high -> standard for ' + principal +
      ' (single factor; methods=' + (methods === null ? 'none' : methods.join('|')) + ')'
    );
    clearance = DEFAULT_CLEARANCE;
    derived.source = derived.source + '+downscoped';
  }

  // Emit onto the access token, for a resource server to authorize against.
  tokenData.clearance = clearance;
  tokenData.mfa = mfa;

  // Mirror onto the id_token so the relying party can render appropriately.
  idtokenData.clearance = clearance;

  // Write it back to the STSUU so any later rule in the chain sees the
  // same value rather than recomputing it and possibly disagreeing.
  stsuu.addAttribute(
    new Attribute('derivedClearance', 'urn:lab:attribute', clearance)
  );

  IDMappingExtUtils.traceString(
    TRACE + 'principal=' + principal +
    ' clearance=' + clearance +
    ' source=' + derived.source +
    ' mfa=' + mfa
  );

})();
