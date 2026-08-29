/**
 * oidc-idtoken-claims.js
 *
 * IBM Verify Identity Access — OIDC pre-token mapping rule.
 * Deploy: AAC > Global Settings > Mapping Rules, category "OAUTH",
 *         then reference from the API Protection definition.
 *
 * PURPOSE
 * -------
 * Release a controlled set of identity attributes as id_token claims.
 *
 * This is the on-premises equivalent of the outbound Attribute Mappings
 * table on a Verify SaaS application's Sign-on tab. SaaS expresses this
 * as a declarative name/source table; here the same release policy is
 * written imperatively, which is what makes conditional and derived
 * claims possible (see oidc-pretoken-derived.js).
 *
 * DATA MINIMISATION
 * -----------------
 * Only the attributes in RELEASE are emitted. Everything else in the
 * STSUniversalUser stays inside the appliance. This is the deliberate
 * alternative to releasing the full attribute set, and it means the
 * question "which claims does this application receive?" is answerable
 * by reading one array.
 */

importPackage(Packages.com.tivoli.am.fim.trustserver.sts);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.uuser);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

// ---------------------------------------------------------------------
// Release policy: STSUU attribute name  ->  claim name in the id_token
// ---------------------------------------------------------------------
var RELEASE = [
  { source: 'department',   claim: 'department',   multi: false },
  { source: 'title',        claim: 'job_title',    multi: false },
  { source: 'groups',       claim: 'groupIds',     multi: true  },
  { source: 'labClearance', claim: 'labClearance', multi: false },
];

var TRACE = 'oidc-idtoken-claims: ';

(function () {

  var principal = stsuu.getPrincipalName();
  if (principal === null) {
    IDMappingExtUtils.traceString(TRACE + 'no principal on STSUU; nothing to map');
    return;
  }

  // sub is the stable subject identifier. Applications must key off this,
  // never off email or username, both of which change.
  idtokenData.sub = principal;

  var attrs = stsuu.getAttributeContainer();
  var released = [];

  for (var i = 0; i < RELEASE.length; i++) {
    var spec = RELEASE[i];

    if (spec.multi) {
      var values = attrs.getAttributeValuesByName(spec.source);
      if (values !== null && values.length > 0) {
        idtokenData[spec.claim] = values;
        released.push(spec.claim);
      }
      continue;
    }

    var value = attrs.getAttributeValueByName(spec.source);

    // An attribute present but empty is not the same as absent. Emitting
    // "" would have a downstream application treat it as a real value.
    if (value !== null && String(value).length > 0) {
      idtokenData[spec.claim] = value;
      released.push(spec.claim);
    }
  }

  IDMappingExtUtils.traceString(
    TRACE + 'principal=' + principal + ' released=[' + released.join(',') + ']'
  );

})();
