# IBM Verify Identity Access — mapping rules and a custom authentication module

JavaScript that runs **inside** IBM Verify Identity Access (the on-premises
product, formerly ISAM / IBM Security Verify Access), together with a local
harness that executes it.

The rules under `rules/` are the artefacts that would be uploaded to an
appliance, unmodified.

    node test/run-tests.js
    26 passed, 0 failed

## Why these exist

The SaaS side of this repository configures attribute release through a
declarative name/source table. That table can only emit attributes that are
already stored on the user.

It cannot compute a value from several inputs, apply precedence between
conflicting sources, vary the result by authentication strength, or refuse
to emit a privileged claim when the authentication was weak.

Those are ordinary requirements, and they are why a mapping rule gets
written instead of a table filled in.

## What is here

| File | Type | Deploys to |
|---|---|---|
| `rules/oidc-idtoken-claims.js` | Pre-token mapping rule | AAC → Global Settings → Mapping Rules, category `OAUTH` |
| `rules/oidc-pretoken-derived.js` | Pre-token mapping rule | Same |
| `rules/infomap-stepup-clearance.js` | **InfoMap** authentication mechanism | AAC → Authentication → Mechanisms → InfoMap Authentication |

### `oidc-idtoken-claims.js`

Releases a controlled set of attributes as `id_token` claims. The on-prem
equivalent of the SaaS outbound attribute-mapping table.

Only attributes named in the `RELEASE` array are emitted, so *"which claims
does this application receive?"* is answered by reading one array. An
attribute that is present but empty is not released — emitting `""` would
have a downstream application treat it as a real value.

### `oidc-pretoken-derived.js`

Derives a `clearance` claim that exists nowhere as a stored attribute:

1. An explicit `labClearance` attribute wins.
2. Otherwise clearance is derived from group membership, most privileged
   group first.
3. Otherwise it defaults to `standard` — never to a privileged value.

It then **downscopes**. `high` is emitted only when the authentication
carried a second factor. A privileged claim minted off a single factor is a
privilege-escalation path: whoever phishes the password inherits the
elevated claim. Here it degrades to `standard` and the reason is written to
the trace for audit.

The resolved value is written back onto the STSUniversalUser so a later
module in the chain sees the same value rather than recomputing it and
possibly disagreeing.

### `infomap-stepup-clearance.js`

A **custom authentication module**. It renders its own login template,
reads request parameters, authenticates against the user registry, resolves
clearance, and publishes the result to the session.

Security properties, each covered by a test:

- **Fail closed.** `success.setValue(false)` is set first and flipped to
  true only on the explicit success path. Every error branch returns with
  it still false.
- **No user enumeration.** An unknown account and a wrong password return
  the identical error string. Distinguishing them turns the login form into
  an account oracle.
- **No ambiguous authentication.** If an email alias matches more than one
  account, the module refuses rather than picking one.
- **Step-up before privilege.** Privileged clearance is granted only when
  the session already carries a second factor.

## Testing

### Locally — `test/ivia-shim.js`

Appliance mapping rules run in a Rhino/Nashorn engine with a set of global
objects already in scope. There is no `require` and no `module.exports`.

The shim reproduces that contract — `stsuu`, `Attribute`, `tokenData`,
`idtokenData`, `IDMappingExtUtils`, and for InfoMap `context`/`Scope`,
`success`, `macros`, `page`, `UserLookupHelper` — and executes each rule
with Node's `vm` module against those globals. `importPackage` and
`importClass` are no-ops; the shim supplies the equivalents directly.

The rule source is therefore identical to what would be deployed. What the
tests exercise is the rule logic, not a reimplementation of it.

```
node test/run-tests.js
```

### On the product — `runjs`

IBM ships a container utility for executing mapping rules without deploying
them. `runjs-input/` holds inputs in its documented format (`clientID`,
`claimjson`, `stsuujson`):

```
docker run --rm \
  --volume $PWD/runjs-input:/var/isvaop/input/ \
  icr.io/ivia/ivia-oidc-provider:<tag> \
  /app/runjs pretoken oidc-pretoken-derived.js pretoken-admin-no-mfa.json
```

| Input | Expected |
|---|---|
| `pretoken-admin-with-mfa.json` | `clearance: "high"`, `mfa: true` |
| `pretoken-admin-no-mfa.json` | `clearance: "standard"` — downscoped, reason in the trace |

## Scope and honesty

These rules are written against IBM's documented mapping-rule API and are
unit-tested against the local shim. **They have not been deployed to a
physical appliance** — the lab tenant available for this work is Verify
SaaS, which does not expose the STS chain.

What is verified here is the logic and the security properties. What would
change on an appliance is the surrounding configuration: the mapping rule
must be registered, referenced from an API protection definition or an
authentication policy, and the InfoMap template deployed to the
authentication service.

## Reference

- [JavaScript mapping rule reference](https://docs.verify.ibm.com/ibm-security-verify-access/docs/js_mapping_rule)
- [Testing mapping rules with runjs](https://docs.verify.ibm.com/ibm-security-verify-access/docs/tasks-runjs)
- [Invoking an STS chain from a mapping rule](https://docs.verify.ibm.com/ibm-security-verify-access/docs/tasks-stschain)
- [WebSEAL overview](https://www.ibm.com/docs/en/sva/11.0.0?topic=web-webseal-overview)
- [Authorization process — protected object space, ACLs, POPs](https://www.ibm.com/docs/en/sva/11.0.0?topic=overview-authorization-process)
