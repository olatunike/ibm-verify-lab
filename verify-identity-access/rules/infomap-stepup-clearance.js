/**
 * infomap-stepup-clearance.js
 *
 * IBM Verify Identity Access — InfoMap authentication mechanism.
 * Deploy: AAC > Authentication > Mechanisms > InfoMap Authentication,
 *         then reference the mechanism from an authentication policy.
 *
 * An InfoMap is a CUSTOM AUTHENTICATION MODULE written in JavaScript.
 * It runs inside the authentication service, can render its own template,
 * read request parameters, call the user registry, and decide the
 * outcome of the authentication step.
 *
 * PURPOSE
 * -------
 * Authenticate the user, then decide whether this session is permitted
 * to hold a privileged clearance — and if so, require that a second
 * factor has already been satisfied.
 *
 * Sequence:
 *   1. No credentials submitted  -> render the login template.
 *   2. Credentials submitted     -> look the user up and authenticate.
 *   3. Authenticated             -> read clearance from the registry.
 *   4. Privileged clearance without a second factor
 *                                -> refuse elevation, continue at
 *                                   standard clearance, record why.
 *   5. Publish the resolved clearance into the session so downstream
 *      mapping rules and policy can consume it.
 *
 * FAIL-CLOSED
 * -----------
 * success.setValue(false) is set first and only flipped to true on the
 * explicit success path. Every error branch returns with it still false.
 * The default outcome of this module is "not authenticated".
 *
 * The same generic error string is returned whether the user does not
 * exist or the password is wrong. Distinguishing them turns the login
 * form into a user-enumeration oracle.
 */

importPackage(Packages.com.tivoli.am.fim.trustserver.sts.utilities);
importClass(Packages.com.ibm.security.access.user.UserLookupHelper);
importClass(Packages.com.ibm.security.access.user.User);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

var TRACE = 'infomap-stepup-clearance: ';

var PARAM_NS   = 'urn:ibm:security:asf:request:parameter';
var SESSION_NS = 'urn:ibm:security:asf:response:token:attributes';

var LOGIN_PAGE     = '/authsvc/authenticator/lab/clearance_login.html';
var GENERIC_ERROR  = 'Username or password is incorrect.';

var PRIVILEGED = ['high', 'elevated'];
var SECOND_FACTORS = ['totp', '2fa', 'fido2', 'otp'];

function isPrivileged(clearance) {
  for (var i = 0; i < PRIVILEGED.length; i++) {
    if (clearance === PRIVILEGED[i]) return true;
  }
  return false;
}

function secondFactorSatisfied() {
  // The authentication service records completed methods on the session.
  var methods = context.get(Scope.SESSION, SESSION_NS, 'authenticationMethods');
  if (methods === null) return false;

  var list = String(methods).toLowerCase().split(',');
  for (var i = 0; i < list.length; i++) {
    for (var j = 0; j < SECOND_FACTORS.length; j++) {
      if (list[i].replace(/^\s+|\s+$/g, '') === SECOND_FACTORS[j]) return true;
    }
  }
  return false;
}

(function () {

  // Fail closed by default.
  success.setValue(false);

  var username = context.get(Scope.REQUEST, PARAM_NS, 'username');
  var password = context.get(Scope.REQUEST, PARAM_NS, 'password');

  // ---- 1. Nothing submitted yet: render the form ---------------------
  if (username === null || password === null) {
    page.setValue(LOGIN_PAGE);
    IDMappingExtUtils.traceString(TRACE + 'no credentials submitted; rendering login page');
    return;
  }

  // ---- 2. Look the user up ------------------------------------------
  var helper = new UserLookupHelper();
  helper.init(true);

  var user = helper.getUser(username);

  if (user === null) {
    // Fall back to an email lookup, but only accept an unambiguous match.
    var found = helper.search('mail', username, 10);

    if (found.length === 1) {
      user = helper.getUserByNativeId(found[0]);
      IDMappingExtUtils.traceString(TRACE + 'resolved by mail alias to ' + found[0]);
    } else if (found.length > 1) {
      // Ambiguous identity must never authenticate: which account would it be?
      IDMappingExtUtils.traceString(TRACE + 'ambiguous mail alias, ' + found.length + ' matches; refusing');
      macros.put('@ERROR_MESSAGE@', GENERIC_ERROR);
      page.setValue(LOGIN_PAGE);
      return;
    }
  }

  if (user === null) {
    // Generic message: do not reveal whether the account exists.
    IDMappingExtUtils.traceString(TRACE + 'no such user; returning generic error');
    macros.put('@ERROR_MESSAGE@', GENERIC_ERROR);
    page.setValue(LOGIN_PAGE);
    return;
  }

  // ---- 3. Authenticate ----------------------------------------------
  if (!user.authenticate(password)) {
    IDMappingExtUtils.traceString(TRACE + 'password check failed for ' + user.getId());
    macros.put('@ERROR_MESSAGE@', GENERIC_ERROR);
    page.setValue(LOGIN_PAGE);
    return;
  }

  // ---- 4. Resolve clearance, downscoping if no second factor ---------
  var clearance = user.getAttribute('labClearance');
  if (clearance === null || String(clearance).length === 0) {
    clearance = 'standard';
  }
  clearance = String(clearance);

  var mfa = secondFactorSatisfied();

  if (isPrivileged(clearance) && !mfa) {
    IDMappingExtUtils.traceString(
      TRACE + 'refusing ' + clearance + ' for ' + user.getId() +
      ': no second factor on this session; continuing at standard'
    );
    clearance = 'standard';
    context.set(Scope.SESSION, SESSION_NS, 'clearanceDownscoped', 'true');
  }

  // ---- 5. Publish to the session ------------------------------------
  context.set(Scope.SESSION, SESSION_NS, 'username', user.getId());
  context.set(Scope.SESSION, SESSION_NS, 'labClearance', clearance);

  success.setValue(true);

  IDMappingExtUtils.traceString(
    TRACE + 'authenticated ' + user.getId() + ' clearance=' + clearance + ' mfa=' + mfa
  );

})();
