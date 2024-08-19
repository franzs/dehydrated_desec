#!/usr/bin/env bash

BASE_API_URL="https://desec.io/api/v1/domains"
TTL=3600
MIN_TTL=3600
DOMAIN_SEPERATOR="."
DESEC_NAMESERVERS=("ns1.desec.io" "ns2.desec.org")
CHALLENGE_RRTYPE="TXT"

if [ -z "${DESEC_TOKEN}" ]; then
  echo "Please set environment variable DESEC_TOKEN." >&2
  exit 1
fi

if [ -f "${CONFIG}" ]; then
  . "${CONFIG}"
fi

desec_add_rrset() {
  local domainname="$1"
  local subdomain="$2"
  local rrtype="$3"
  local content="$4"
  local ttl="${5:-${MIN_TTL}}"

  if [ "${ttl}" -lt ${MIN_TTL} ]; then
    echo "TTL must be at least ${MIN_TTL} s. Adjusting." >&2
    ttl=${MIN_TTL}
  fi

  if [ "${rrtype}" = "TXT" ] && [ "${content:0-1}" != '"' ]; then
    content='\"'"${content}"'\"'
  fi

  echo "Adding ${subdomain}${DOMAIN_SEPERATOR}${domain_name}"

  curl -sS -X POST "${BASE_API_URL}/${domainname}/rrsets/" \
    --header "Authorization: Token ${DESEC_TOKEN}" \
    --header "Content-Type: application/json" --data \
    "{\"subname\": \"${subdomain}\", \"type\": \"${rrtype}\", \"ttl\": ${ttl}, \"records\": [\"${content}\"]}" |
    jq .
}

desec_remove_rrset() {
  local domainname="$1"
  local subdomain="$2"
  local rrtype="$3"

  echo "Removing ${subdomain}${DOMAIN_SEPERATOR}${domain_name}"

  curl -sS -X DELETE "${BASE_API_URL}/${domainname}/rrsets/${subdomain}/${rrtype}/" \
    --header "Authorization: Token ${DESEC_TOKEN}"
}

desec_responsible_domain() {
  local qname="$1"

  curl -sS -X GET "${BASE_API_URL}/?owns_qname=${qname}" \
    --header "Authorization: Token ${DESEC_TOKEN}" |
    jq -r '.[0].name'
}

desec_subdomain_name() {
  local domain="$1"
  local domain_name="$2"

  if [ "${domain}" = "${domain_name}" ]; then
    echo ""
  else
    echo "${domain%"${DOMAIN_SEPERATOR}""${domain_name}"}"
  fi
}

desec_challenge_name() {
  local subdomain="$1"

  if [ -z "${subdomain}" ]; then
    echo "_acme-challenge"
  else
    echo "_acme-challenge${DOMAIN_SEPERATOR}${subdomain}"
  fi
}

deploy_challenge() {
  local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"

  # This hook is called once for every domain that needs to be
  # validated, including any alternative names you may have listed.
  #
  # Parameters:
  # - DOMAIN
  #   The domain name (CN or subject alternative name) being
  #   validated.
  # - TOKEN_FILENAME
  #   The name of the file containing the token to be served for HTTP
  #   validation. Should be served by your web server as
  #   /.well-known/acme-challenge/${TOKEN_FILENAME}.
  # - TOKEN_VALUE
  #   The token value that needs to be served for validation. For DNS
  #   validation, this is what you want to put in the _acme-challenge
  #   TXT record. For HTTP validation it is the value that is expected
  #   be found in the $TOKEN_FILENAME file.

  local domain_name
  local subdomain_name
  local challenge_name
  local query_result

  domain_name="$(desec_responsible_domain "${DOMAIN}")"

  if [ "${domain_name}" = "null" ]; then
    echo "No responsible domain for ${DOMAIN} found." >&2
    exit 1
  fi

  subdomain_name="$(desec_subdomain_name "${DOMAIN}" "${domain_name}")"
  challenge_name="$(desec_challenge_name "${subdomain_name}")"

  desec_add_rrset "${domain_name}" "${challenge_name}" "${CHALLENGE_RRTYPE}" "${TOKEN_VALUE}" "${TTL}"

  echo -ne "\nWaiting for record activation"

  while true; do
    sleep 3
    echo -n "."

    for nameserver in "${DESEC_NAMESERVERS[@]}"; do
      query_result="$(dig @"${nameserver}." "${challenge_name}${DOMAIN_SEPERATOR}${domain_name}." "${CHALLENGE_RRTYPE}" +short)"

      if [ -z "${query_result}" ]; then
        continue 2
      fi
    done

    break
  done

  # give some extra time
  for i in {1..4}; do
    sleep 3
    echo -n "."
  done

  echo
}

clean_challenge() {
  local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"

  # This hook is called after attempting to validate each domain,
  # whether or not validation was successful. Here you can delete
  # files or DNS records that are no longer needed.
  #
  # The parameters are the same as for deploy_challenge.

  local domain_name
  local subdomain_name
  local challenge_name

  domain_name="$(desec_responsible_domain "${DOMAIN}")"

  if [ "${domain_name}" = "null" ]; then
    echo "No responsible domain for ${DOMAIN} found." >&2
    exit 1
  fi

  subdomain_name="$(desec_subdomain_name "${DOMAIN}" "${domain_name}")"
  challenge_name="$(desec_challenge_name "${subdomain_name}")"

  desec_remove_rrset "${domain_name}" "${challenge_name}" "${CHALLENGE_RRTYPE}"
}

deploy_cert() {
  local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}" TIMESTAMP="${6}"

  # This hook is called once for each certificate that has been
  # produced. Here you might, for instance, copy your new certificates
  # to service-specific locations and reload the service.
  #
  # Parameters:
  # - DOMAIN
  #   The primary domain name, i.e. the certificate common
  #   name (CN).
  # - KEYFILE
  #   The path of the file containing the private key.
  # - CERTFILE
  #   The path of the file containing the signed certificate.
  # - FULLCHAINFILE
  #   The path of the file containing the full certificate chain.
  # - CHAINFILE
  #   The path of the file containing the intermediate certificate(s).
  # - TIMESTAMP
  #   Timestamp when the specified certificate was created.

  if [ -n "${HOOK_DEPLOY_CERT}" ] && [ -x "${HOOK_DEPLOY_CERT}" ]; then
    echo "Executing ${HOOK_DEPLOY_CERT}"

    "${HOOK_DEPLOY_CERT}" "${DOMAIN}" "${KEYFILE}" "${CERTFILE}" "${FULLCHAINFILE}" "${CHAINFILE}" "${TIMESTAMP}"
  fi
}

HANDLER="$1"
shift
if [[ "${HANDLER}" =~ ^(deploy_challenge|clean_challenge|deploy_cert)$ ]]; then
  "$HANDLER" "$@"
fi
