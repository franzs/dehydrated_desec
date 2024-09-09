#!/usr/bin/env bash

BASE_API_URL="https://desec.io/api/v1/domains"
TTL=3600
MIN_TTL=3600
DOMAIN_SEPARATOR="."
DESEC_NAMESERVERS=("ns1.desec.io" "ns2.desec.org")
CHALLENGE_RRTYPE="TXT"
POLLING_INTERVAL=3
POLLING_TIMEOUT=240

declare -g curl_temp_file

if [ -f "${CONFIG}" ]; then
  # shellcheck source=/dev/null
  . "${CONFIG}"
fi

remove_curl_temp_file() {
  if [ -f "${curl_temp_file}" ]; then
    rm -f "${curl_temp_file}"
  fi
}

desec_authorization_header() {
  echo "Authorization: Token ${DESEC_TOKEN}"
}

desec_add_rrset() {
  local domainname="$1"
  local subdomain="$2"
  local rrtype="$3"
  local content="$4"
  local ttl="${5:-${MIN_TTL}}"

  local curl_http_code

  if [ "${ttl}" -lt ${MIN_TTL} ]; then
    echo "TTL must be at least ${MIN_TTL} s. Adjusting." >&2
    ttl=${MIN_TTL}
  fi

  if [ "${rrtype}" = "TXT" ] && [ "${content:0-1}" != '"' ]; then
    content='\"'"${content}"'\"'
  fi

  curl_temp_file=$(mktemp)
  trap 'remove_curl_temp_file' EXIT

  echo "Adding ${subdomain}${DOMAIN_SEPARATOR}${domainname}"

  curl_http_code=$(curl -sS \
    --output "${curl_temp_file}" \
    --write-out "%{http_code}" \
    --request POST \
    --header "$(desec_authorization_header)" \
    --header "Content-Type: application/json" \
    --data "{\"subname\": \"${subdomain}\", \"type\": \"${rrtype}\", \"ttl\": ${ttl}, \"records\": [\"${content}\"]}" \
    "${BASE_API_URL}/${domainname}/rrsets/")

  if [ "${curl_http_code}" != "201" ]; then
    echo "Adding record failed:"
    jq . <"${curl_temp_file}"
    exit 1
  fi
}

desec_remove_rrset() {
  local domainname="$1"
  local subdomain="$2"
  local rrtype="$3"

  echo "Removing ${subdomain}${DOMAIN_SEPARATOR}${domainname}"

  curl -sS \
    --request DELETE \
    --header "$(desec_authorization_header)" \
    "${BASE_API_URL}/${domainname}/rrsets/${subdomain}/${rrtype}/"
}

desec_responsible_domain() {
  local qname="$1"

  curl -sS \
    --request GET \
    --header "$(desec_authorization_header)" \
    "${BASE_API_URL}/?owns_qname=${qname}" |
    jq -r '.[0].name'
}

desec_subdomain_name() {
  local domain="$1"
  local domain_name="$2"

  if [ "${domain}" = "${domain_name}" ]; then
    echo ""
  else
    echo "${domain%"${DOMAIN_SEPARATOR}""${domain_name}"}"
  fi
}

desec_challenge_name() {
  local subdomain="$1"

  if [ -z "${subdomain}" ]; then
    echo "_acme-challenge"
  else
    echo "_acme-challenge${DOMAIN_SEPARATOR}${subdomain}"
  fi
}

deploy_challenge() {
  # shellcheck disable=SC2034
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
  local start_time
  local current_time

  domain_name="$(desec_responsible_domain "${DOMAIN}")"

  if [ "${domain_name}" = "null" ]; then
    echo "No responsible domain for ${DOMAIN} found." >&2
    exit 1
  fi

  subdomain_name="$(desec_subdomain_name "${DOMAIN}" "${domain_name}")"
  challenge_name="$(desec_challenge_name "${subdomain_name}")"

  desec_add_rrset "${domain_name}" "${challenge_name}" "${CHALLENGE_RRTYPE}" "${TOKEN_VALUE}" "${TTL}"

  sleep 1
}

wait_for_challenge() {
  # shellcheck disable=SC2034
  local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"

  local challenge_name

  challenge_name="$(desec_challenge_name "${DOMAIN}")"

  echo -n "Waiting for record activation ${challenge_name} "

  start_time=$(date +%s)

  while true; do
    current_time=$(date +%s)

    if [ $((current_time - start_time)) -gt ${POLLING_TIMEOUT} ]; then
      echo
      echo "Waited more than ${POLLING_TIMEOUT} s for record activation. Giving up."
      return
    fi

    for nameserver in "${DESEC_NAMESERVERS[@]}"; do
      query_result="$(dig @"${nameserver}." "${challenge_name}." "${CHALLENGE_RRTYPE}" +short)"

      if [ -z "${query_result}" ]; then
        sleep ${POLLING_INTERVAL}
        echo -n "."

        continue 2
      fi
    done

    break
  done

  echo
}

extra_wait_time() {
  local extra_wait_time=12

  # give some extra time
  start_time=$(date +%s)

  echo -n "Waiting a bit longer "

  while true; do
    current_time=$(date +%s)

    if [ $((current_time - start_time)) -ge ${extra_wait_time} ]; then
      break
    fi

    sleep ${POLLING_INTERVAL}
    echo -n "."
  done

  echo
}

clean_challenge() {
  # shellcheck disable=SC2034
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

  sleep 1
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

startup_hook() {
  # This hook is called before the cron command to do some initial tasks
  # (e.g. starting a webserver).

  local exit=0

  if [ -z "${DESEC_TOKEN}" ]; then
    echo "A token is needed for deSEC. Please set environment variable DESEC_TOKEN." >&2
    exit=1
  fi

  for cmd in curl jq; do
    if ! type -t "${cmd}" >/dev/null; then
      echo "${cmd} is needed. Please install it." >&2
      exit=1
    fi
  done

  [ ${exit} -ne 0 ] && exit ${exit}

  :
}

HANDLER="$1"
shift

if [[ "${HANDLER}" =~ ^(deploy_challenge|clean_challenge)$ ]]; then
  declare -a saved_args=("${@}")

  while [ $# -ge 3 ]; do
    "$HANDLER" "$1" "$2" "$3"
    shift 3
  done

  if [ "${HANDLER}" = "deploy_challenge" ]; then
    set -- "${saved_args[@]}"

    while [ $# -ge 3 ]; do
      wait_for_challenge "$1" "$2" "$3"
      shift 3
    done

    extra_wait_time
  fi
elif [[ "${HANDLER}" =~ ^(deploy_cert|startup_hook)$ ]]; then
  "$HANDLER" "$@"
fi
