#!/usr/bin/env bash

BASE_API_URL="https://desec.io/api/v1/domains"
TTL=3600
DOMAIN_SEPERATOR="."
DESEC_NAMESERVERS=("ns1.desec.io" "ns2.desec.org")
CHALLENGE_RRTYPE="TXT"
DUMMY_CONTENT="DUMMY-CONTENT-FOR-DEHYDRATED"

if [ -z "${DESEC_TOKEN}" ]; then
  echo "Please set environment variable DESEC_TOKEN." >&2
  exit 1
fi

if [ -f "${CONFIG}" ]; then
  . "${CONFIG}"
fi

desec_check_rrset() {
  local domainname="$1"
  local subdomain="$2"
  local rrtype="$3"

  local result_subname

  result_subname="$(curl -sS "${BASE_API_URL}/${domainname}/rrsets/${subdomain}/${rrtype}/" \
    --header "Authorization: Token ${DESEC_TOKEN}" | jq -r '.records[0]' | sed -e 's/^"//; s/"$//;')"

  echo "${result_subname}"
}

desec_add_rrset() {
  local domainname="$1"
  local subdomain="$2"
  local rrtype="$3"
  local content="$4"
  local ttl="${5:-3600}"

  if [ "${ttl}" -lt 3600 ]; then
    echo "TTL must be at least 3600 s. Adjusting." >&2
    ttl=3600
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

desec_subdomain_name() {
  local domain="$1"

  cut -d "${DOMAIN_SEPERATOR}" -f 1 <<<"${domain}"
}

desec_domain_name() {
  local domain="$1"

  cut -d "${DOMAIN_SEPERATOR}" -f 2- <<<"${domain}"
}

desec_challenge_name() {
  local subdomain="$1"

  echo "_acme-challenge${DOMAIN_SEPERATOR}${subdomain}"
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

  local domain_name="$(desec_domain_name "${DOMAIN}")"
  local subdomain_name="$(desec_subdomain_name "${DOMAIN}")"
  local challenge_name="$(desec_challenge_name "${subdomain_name}")"

  local check_result
  local query_result

  check_result="$(desec_check_rrset "${domain_name}" "${subdomain_name}" "${CHALLENGE_RRTYPE}")"

  if [ "${check_result}" = "null" ]; then
    desec_add_rrset "${domain_name}" "${subdomain_name}" "${CHALLENGE_RRTYPE}" "${DUMMY_CONTENT}" "${TTL}"
  fi

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

  local domain_name="$(desec_domain_name "${DOMAIN}")"
  local subdomain_name="$(desec_subdomain_name "${DOMAIN}")"
  local challenge_name="$(desec_challenge_name "${subdomain_name}")"

  local check_result

  desec_remove_rrset "${domain_name}" "${challenge_name}" "${CHALLENGE_RRTYPE}"

  check_result="$(desec_check_rrset "${domain_name}" "${subdomain_name}" "${CHALLENGE_RRTYPE}")"

  if [ "${check_result}" = "${DUMMY_CONTENT}" ]; then
    desec_remove_rrset "${domain_name}" "${subdomain_name}" "${CHALLENGE_RRTYPE}"
  fi
}

sync_cert() {
  local KEYFILE="${1}" CERTFILE="${2}" FULLCHAINFILE="${3}" CHAINFILE="${4}" REQUESTFILE="${5}"

  # This hook is called after the certificates have been created but before
  # they are symlinked. This allows you to sync the files to disk to prevent
  # creating a symlink to empty files on unexpected system crashes.
  #
  # This hook is not intended to be used for further processing of certificate
  # files, see deploy_cert for that.
  #
  # Parameters:
  # - KEYFILE
  #   The path of the file containing the private key.
  # - CERTFILE
  #   The path of the file containing the signed certificate.
  # - FULLCHAINFILE
  #   The path of the file containing the full certificate chain.
  # - CHAINFILE
  #   The path of the file containing the intermediate certificate(s).
  # - REQUESTFILE
  #   The path of the file containing the certificate signing request.

  # Simple example: sync the files before symlinking them
  # sync "${KEYFILE}" "${CERTFILE}" "${FULLCHAINFILE}" "${CHAINFILE}" "${REQUESTFILE}"
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

deploy_ocsp() {
  local DOMAIN="${1}" OCSPFILE="${2}" TIMESTAMP="${3}"

  # This hook is called once for each updated ocsp stapling file that has
  # been produced. Here you might, for instance, copy your new ocsp stapling
  # files to service-specific locations and reload the service.
  #
  # Parameters:
  # - DOMAIN
  #   The primary domain name, i.e. the certificate common
  #   name (CN).
  # - OCSPFILE
  #   The path of the ocsp stapling file
  # - TIMESTAMP
  #   Timestamp when the specified ocsp stapling file was created.

  # Simple example: Copy file to nginx config
  # cp "${OCSPFILE}" /etc/nginx/ssl/; chown -R nginx: /etc/nginx/ssl
  # systemctl reload nginx
}

unchanged_cert() {
  local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}"

  # This hook is called once for each certificate that is still
  # valid and therefore wasn't reissued.
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
}

invalid_challenge() {
  local DOMAIN="${1}" RESPONSE="${2}"

  # This hook is called if the challenge response has failed, so domain
  # owners can be aware and act accordingly.
  #
  # Parameters:
  # - DOMAIN
  #   The primary domain name, i.e. the certificate common
  #   name (CN).
  # - RESPONSE
  #   The response that the verification server returned

  # Simple example: Send mail to root
  # printf "Subject: Validation of ${DOMAIN} failed!\n\nOh noez!" | sendmail root
}

request_failure() {
  local STATUSCODE="${1}" REASON="${2}" REQTYPE="${3}" HEADERS="${4}"

  # This hook is called when an HTTP request fails (e.g., when the ACME
  # server is busy, returns an error, etc). It will be called upon any
  # response code that does not start with '2'. Useful to alert admins
  # about problems with requests.
  #
  # Parameters:
  # - STATUSCODE
  #   The HTML status code that originated the error.
  # - REASON
  #   The specified reason for the error.
  # - REQTYPE
  #   The kind of request that was made (GET, POST...)
  # - HEADERS
  #   HTTP headers returned by the CA

  # Simple example: Send mail to root
  # printf "Subject: HTTP request failed failed!\n\nA http request failed with status ${STATUSCODE}!" | sendmail root
}

generate_csr() {
  local DOMAIN="${1}" CERTDIR="${2}" ALTNAMES="${3}"

  # This hook is called before any certificate signing operation takes place.
  # It can be used to generate or fetch a certificate signing request with external
  # tools.
  # The output should be just the certificate signing request formatted as PEM.
  #
  # Parameters:
  # - DOMAIN
  #   The primary domain as specified in domains.txt. This does not need to
  #   match with the domains in the CSR, it's basically just the directory name.
  # - CERTDIR
  #   Certificate output directory for this particular certificate. Can be used
  #   for storing additional files.
  # - ALTNAMES
  #   All domain names for the current certificate as specified in domains.txt.
  #   Again, this doesn't need to match with the CSR, it's just there for convenience.

  # Simple example: Look for pre-generated CSRs
  # if [ -e "${CERTDIR}/pre-generated.csr" ]; then
  #   cat "${CERTDIR}/pre-generated.csr"
  # fi
}

startup_hook() {
  # This hook is called before the cron command to do some initial tasks
  # (e.g. starting a webserver).

  :
}

exit_hook() {
  local ERROR="${1:-}"

  # This hook is called at the end of the cron command and can be used to
  # do some final (cleanup or other) tasks.
  #
  # Parameters:
  # - ERROR
  #   Contains error message if dehydrated exits with error
}

HANDLER="$1"
shift
if [[ "${HANDLER}" =~ ^(deploy_challenge|clean_challenge|sync_cert|deploy_cert|deploy_ocsp|unchanged_cert|invalid_challenge|request_failure|generate_csr|startup_hook|exit_hook)$ ]]; then
  "$HANDLER" "$@"
fi
