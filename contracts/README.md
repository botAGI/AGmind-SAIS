# Contract validation authority

The Draft 2020-12 files provide the portable structural layer: required fields,
closed objects, patterns, enums, and scalar bounds. They are not sufficient on
their own for an authorization decision when a schema declares
`x-agmind-semantic`.

An authoritative consumer of such a schema must:

1. reject duplicate keys, floating-point wire values, non-finite numbers, and
   trailing JSON before schema validation;
2. enforce the named `x-agmind-semantic` contract with strict, non-coercing
   types and every cross-field arithmetic, endpoint, and digest binding; and
3. fail closed if the semantic marker is unknown or unsupported.

The canonical Python path is `contract_schema_validator` plus the strict
contract models. The Go path uses its strict decoder and the matching typed
`Validate` methods. A standards-only JSON Schema validator that silently
ignores `x-agmind-semantic` is a structural checker, not a contract-authority
or mutation-authority validator.
