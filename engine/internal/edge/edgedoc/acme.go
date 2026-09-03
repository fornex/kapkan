package edgedoc

// DefaultACMEDirectory is the CA a node uses when neither the zone nor the
// node names one: Let's Encrypt production. Defined here — the leaf every
// edge package imports — so the ACME manager's default and the node
// configuration's validation (a fallback equal to the default is a no-op)
// cannot drift apart.
const DefaultACMEDirectory = "https://acme-v02.api.letsencrypt.org/directory"
