# dehydrated Hook for deSEC

This repository provides a custom hook for [dehydrated](https://github.com/dehydrated-io/dehydrated/), a client for managing Let's Encrypt certificates. The hook leverages the [deSEC API](https://desec.readthedocs.io/en/latest/index.html) to handle DNS challenges for the [dns-01](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge) method.

## Setup

To use the hook set the `CHALLENGE_TYPE` and `HOOK` variable in your dehydrated config:

```bash
CHALLENGETYPE="dns-01"
HOOK="<path to repo>/dehydrated_desec/hook.sh"
```

In addition, this hook allows to use a script for deploying certs, e. g.

```bash
HOOK_DEPLOY_CERT="${SOME_DIR}/deploy_cert.sh"
```

The script is called with these parameters:

```bash
"${HOOK_DEPLOY_CERT}" "${DOMAIN}" "${KEYFILE}" "${CERTFILE}" "${FULLCHAINFILE}" "${CHAINFILE}" "${TIMESTAMP}"
```

- `DOMAIN`:  The primary domain name, i.e. the certificate common name (CN).
- `KEYFILE`: The path of the file containing the private key.
- `CERTFILE`: The path of the file containing the signed certificate.
- `FULLCHAINFILE`: The path of the file containing the full certificate chain.
- `CHAINFILE`: The path of the file containing the intermediate certificate(s).
- `TIMESTAMP`: Timestamp when the specified certificate was created.
