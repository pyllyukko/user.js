#!/bin/bash

# life_without_ca.sh -- a script that creates a very limited set of root CAs to your firefox's cert8.db

# before you use this script, i suggest you run certpatrol for something like half a year to get enough certificate "samples"

# here's roughly what this script does:
#
# - build index of CAs from operating systems global cert store (${CERT_PATH})
# - build index of (intermediate) CAs from firefox's cert8.db cert store
# - get issuers from all the certificates seen from certificate patrol's CertPatrol.sqlite DB
# - try to locate the CA from the global index
# - if that doesn't work out (when the issuer is an intermediate CA), try to locate the intermediate CA from the cert8.db index (as firefox caches the intermediate CAs)
#   - try to find the CA of that
# - construct at list of required _root_ CAs
#   - locate those from ${CERT_PATH}
#   - import to (new) cert8.db
#     - note that you must have removed the libnssckbi.so cert library, so firefox doesn't use it's bloated CA store (for more info, see: https://blog.torproject.org/blog/life-without-ca)
#   - set trusted to verify websites
# - profit?

# TODO:
#   - add openssl verify magic
#   - we could construct the required CAs list from only the intermediate CAs in cert8.db, although it will not be complete
#   - use /usr/share/ca-certificates instead of ${CERT_PATH}
#   - search all sites from certpatrol, that use CA <x>
#   - events.ccc.de - /usr/share/ca-certificates/cacert.org/cacert.org.crt -> should we include this? maybe as untrusted?
#   - crawl Firefox history for HTTPS sites and get certs?
#
# domains that don't work (use some other CA):
#   - kb.wisc.edu

for PROGRAM in \
  gawk \
  openssl \
  certutil \
  sqlite3
do
  if ! hash "${PROGRAM}" 2>/dev/null
  then
    printf "error: command not found in PATH: %s\n" "${PROGRAM}" >&2
    exit 1
  fi
done
unset PROGRAM

# from http://wiki.bash-hackers.org/scripting/debuggingtips#making_xtrace_more_useful:
export PS4='+(${BASH_SOURCE}:${LINENO}): ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'
declare -A CAs=()
declare -A CERT8_CAs=()
declare -A CERT8_NICKS=()
# this uses all the available firefox profiles
INDEX_ALL_CERT8=0
declare -a BASIC_LIST=(
  "mozilla/AddTrust_External_Root.crt"
  "mozilla/Baltimore_CyberTrust_Root.crt"
  "mozilla/COMODO_Certification_Authority.crt"
  "mozilla/Deutsche_Telekom_Root_CA_2.crt"
  "mozilla/DigiCert_High_Assurance_EV_Root_CA.crt"
  "mozilla/DigiCert_Global_Root_CA.crt"
  "mozilla/Entrust.net_Secure_Server_CA.crt"
  "mozilla/Entrust.net_Premium_2048_Secure_Server_CA.crt"
  "mozilla/Equifax_Secure_CA.crt"
  "mozilla/GTE_CyberTrust_Global_Root.crt"
  "mozilla/GeoTrust_Global_CA.crt"
  "mozilla/GlobalSign_Root_CA.crt"
  "mozilla/Go_Daddy_Class_2_CA.crt"
  "mozilla/Go_Daddy_Root_Certificate_Authority_-_G2.crt"
  "mozilla/Starfield_Class_2_CA.crt"
  "mozilla/StartCom_Certification_Authority.crt"
  "mozilla/UTN_USERFirst_Hardware_Root_CA.crt"
  "mozilla/ValiCert_Class_2_VA.crt"
  "mozilla/VeriSign_Class_3_Public_Primary_Certification_Authority_-_G5.crt"
  "mozilla/thawte_Primary_Root_CA.crt"
  "mozilla/SecureTrust_CA.crt"
)
CERT_PATH="$( openssl version -a|grep "^OPENSSLDIR:"|cut -d'"' -f2 )/certs"
WRN=$'\033[1;31m'
RST=$'\033[0m'
DEBUG=0

function import_cas() {
  local REQUIRED_CA
  local NICKNAME

  if [ -z "${FF_HOME}" ]
  then
    echo "${FUNCNAME}(): error: FF_HOME not defined!" 1>&2
    return 1
  fi

  echo -e "\nimporting CAs:"
  # create cert8.db for the new profile
  for REQUIRED_CA in ${REQUIRED_CAs[*]}
  do
    #if [ "${REQUIRED_CA:0:1}" != "/" ]
    #then
    #  REQUIRED_CA="${CERT_PATH}/${REQUIRED_CA}"
    #fi
    if [ ! -f "${REQUIRED_CA}" ]
    then
      echo "error: file \`${REQUIRED_CA}' not found!" 1>&2
      continue
    fi
    echo "  ${REQUIRED_CA}"
    # certutil requires a "nickname", so we'll use the CN or OU
    # TODO: change this?
    NICKNAME=$( openssl x509 -in "${REQUIRED_CA}" -noout -subject | sed 's/^.*\(CN\|OU\)=//' )
    cat "${REQUIRED_CA}" | certutil -A -n "${NICKNAME}" -t CT,c,c -a -d "${FF_HOME}"

    # TEST!!! allow code signing
    #cat "${REQUIRED_CA}" | certutil -A -n "${NICKNAME}" -t CT,c,C -a -d "${FF_HOME}"
  done

  return
} # import_cas()

function expand_cert_path() {
  # this function follows symlinked files, until the actual file is found.
  local FILE="${1}"
  if [ ! -f "${FILE}" ]
  then
    echo "${FUNCNAME}(): error: file \`${FILE}' not found!" 1>&2
    return 1
  fi
  while [ -h "${FILE}" ]
  do
    FILE=$( readlink "${FILE}" )
    if [ "${FILE:0:1}" != "/" ]
    then
      FILE="${CERT_PATH}/${FILE}"
    fi
  done
  echo "${FILE}"
  return
} # expand_cert_path()

function get_required_cas_list() {
  local    FINGERPRINT
  local -a FINGERPRINTS
  local    REQUIRED_CA
  local    ISSUER
  local    ISSUER_CN

  if [ -z "${CP}" ]
  then
    echo "error: no CertPatrol path defined!" 1>&2
    return 1
  elif [ ! -f "${CP}" ]
  then
    echo "error: certpatrol DB \`${CP}' not found!" 1>&2
    return 1
  fi

  # read all the issuer fingerprints from certificate patrol's DB
  echo "reading issuer fingerprints from certpatrol's DB"
  FINGERPRINTS=( $( sqlite3 ${CP} 0<<<"select distinct issuerSha1Fingerprint from certificates where issuerSha1Fingerprint is not '';" ) )
  echo -e "${#FINGERPRINTS[*]} issuer fingerprints found\n"
  for FINGERPRINT in ${FINGERPRINTS[*]}
  do
    REQUIRED_CA=""
    # check if the issuer cert is a root CA
    if [ -n "${CAs[${FINGERPRINT}]}" ]
    then
      echo "${FINGERPRINT}: root CA found: ${CAs[${FINGERPRINT}]}"
      REQUIRED_CA="${CAs[${FINGERPRINT}]}"
      # TODO: openssl verify
    # this is the most common case, as the certs are usually signed by intermediate CA
    elif [ -n "${CERT8_CAs[${FINGERPRINT}]}" ]
    then
      echo "${FINGERPRINT}: found on cert8.db \"${CERT8_CAs[${FINGERPRINT}]}\""

      # find the root CA that signed the intermediate CA
      # TODO: it would be better to get the fingerprint of the issuer, instead of issuer_hash
      ISSUER=$( certutil -L -n "${CERT8_CAs[${FINGERPRINT}]}" -a -d "${OLD_FF_HOME}" | openssl x509 -noout -issuer_hash )
      # TODO: iterate through n
      REQUIRED_CA=$( expand_cert_path "${CERT_PATH}/${ISSUER}.0" 2>/dev/null )
      if [ -z "${REQUIRED_CA}" ]
      then
	# TODO: check if the cert actually is root CA
	echo -e "  ${WRN}WARNING${RST}: no root CA found for this cert -> continue"
        continue
      fi
      echo "  root CA found on file system: ${REQUIRED_CA}"

      # verify
      #certutil -L -n "${CERT8_CAs[${FINGERPRINT}]}" -a -d "${OLD_FF_HOME}" | openssl verify -CAfile "${REQUIRED_CA}"
    else
      # issuer cert not found
      if (( ${DEBUG} ))
      then
        ISSUER_CN=$( sqlite3 ${CP} 0<<<"select distinct issuerCommonName from certificates where issuerSha1Fingerprint is \"${FINGERPRINT}\";" )
        echo -e "${FINGERPRINT}: \033[1;31mnot\033[0m found \"${ISSUER_CN}\"!" 1>&2
        # print hosts that use this issuer
	echo "  sites that use this CA:"
        sqlite3 ${CP} 0<<<"select host from certificates where issuerSha1Fingerprint is \"${FINGERPRINT}\";" | sed 's/^/    /'
      fi
    fi
    if [ -n "${REQUIRED_CA}" ]
    then
      REQUIRED_CAs+=( ${REQUIRED_CA} )
    fi
  done # for FINGERPRINT
  # UGLY HACK WARNING!
  REQUIRED_CAs=( $( tr ' ' '\n' 0<<<"${REQUIRED_CAs[*]}" | sort -u ) )

  return
} # get_required_cas_list()

function print_required_cas_list() {
  local REQUIRED_CA

  echo -e "\n\nrequired CAs (${#REQUIRED_CAs[*]}):"
  for REQUIRED_CA in ${REQUIRED_CAs[*]}
  do
    echo "  ${REQUIRED_CA}"
    if [ ! -f "${REQUIRED_CA}" ]
    then
      echo "    WARNING: not found!" 1>&2
    fi
  done

  return
} # print_required_cas_list()

function print_countries() {
  local -a NICKNAMES
  local    NICKNAME
  local    OIFS
  local    COUNTRY
  OIFS=${IFS}
  IFS=$'\n'
  # get the "nicknames", as this is the way certutil handles the certs
  NICKNAMES=( $( certutil -L -d "${FF_HOME}" | fgrep -v ",," | sed '1,4d' | gawk 'NF--' ) )
  IFS=${OIFS}
  for NICKNAME in "${NICKNAMES[@]}"
  do
    # print the PEM from the cert8.db and get the FP with openssl
    COUNTRY=$( certutil -L -n "${NICKNAME}" -a -d "${FF_HOME}" | openssl x509 -noout -subject | grep -o "C=[A-Z]\+" )
    if [ -n "${COUNTRY}" ]
    then
      echo "${COUNTRY#C=}"
    else
      echo "warning: country not found for \`${NICKNAME}'!" 1>&2
    fi
  done | sort | uniq -c

} # print_countries()

function reverse_index() {
  # this builds an index of the cert8.db nicknames

  local -a NICKNAMES
  local    NICKNAME
  local    OIFS
  local -a FPS=()
  local    FP

  if [ -z "${FF_HOME}" ]
  then
    echo "${FUNCNAME}(): error: FF_HOME not defined!" 1>&2
    return 1
  fi

  OIFS=${IFS}
  IFS=$'\n'
  NICKNAMES=( $( certutil -L -d "${FF_HOME}" | sed '1,4d' | fgrep -v ',,' | gawk 'NF--' ) )
  IFS=${OIFS}

  for NICKNAME in "${NICKNAMES[@]}"
  do
    # print the PEM from the cert8.db and get the FP with openssl
    FP=$( certutil -L -n "${NICKNAME}" -a -d "${FF_HOME}" | openssl x509 -noout -fingerprint -sha1 | sed 's/^.*Fingerprint=//' )
    if [ -z "${FP}" ]
    then
      echo "WARNING: could not get fingerprint for \`${NICKNAME}'!" 1>&2
    fi
    #FPS+=( $( certutil -L -n "${NICKNAME}" -a -d "${FF_HOME}" | openssl x509 -noout -fingerprint -sha1 | sed 's/^.*Fingerprint=//' ) )
    FPS+=( ${FP} )
  done

  echo -e "reverse index:\n"

  for FP in ${FPS[*]}
  do
    if [ -n "${CAs[${FP}]}" ]
    then
      echo "${CAs[${FP}]}"
    else
      echo "WARNING: \`${NICKNAME}' not found (fp=${FP})!" 1>&2
    fi
  done

  echo -n $'\n'
} # reverse_index()

function index_cas() {
  local    FILE
  local -a FILES=()
  local    FP
  local    NICKNAME
  local    OIFS
  local -a CERT8S=()
  local    CERT8
  local -a NICKNAMES

  # index the certs to CAs[] associative array
  echo "indexing ${CERT_PATH}"

  # dereference symbolic links
  for FILE in ${CERT_PATH}/*
  do
    if [ ! -f "${FILE}" ]
    then
      continue
    fi
    FILE=$( expand_cert_path "${FILE}" )
    FILES+=( "${FILE}" )
  done

  for FILE in ${FILES[*]}
  do
    if [ ! -f "${FILE}" ]
    then
      continue
    fi
    FP=$( openssl x509 -in "${FILE}" -noout -fingerprint -sha1 | sed 's/^.*Fingerprint=//' )
    if [ -n "${FP}" ]
    then
      CAs["${FP}"]="${FILE}"
    fi
  done

  echo -e "${#CAs[*]} CAs\n"

  if [ -z "${OLD_FF_HOME}" ]
  then
    echo "${FUNCNAME}(): WARNING: OLD_FF_HOME not defined -> returning" 1>&2
    return 1
  fi

  # cert8.db
  # use all available firefox profiles
  if (( ${INDEX_ALL_CERT8} ))
  then
    OIFS=${IFS}
    IFS=$'\n'
    # find all cert8.db files under ~/.mozilla/firefox
    CERT8S=( $( find ~/.mozilla/firefox -type f -name cert8.db | sed 's/\/cert8\.db$//' ) )
    IFS=${OIFS}
  else
    CERT8S=( "${OLD_FF_HOME}" )
  fi
  for CERT8 in "${CERT8S[@]}"
  do
    echo "indexing cert8.db from \`${CERT8}'"
    OIFS=${IFS}
    IFS=$'\n'
    # get the "nicknames", as this is the way certutil handles the certs
    NICKNAMES=( $( certutil -L -d "${CERT8}" | sed '1,4d' | gawk 'NF--' ) )
    IFS=${OIFS}
    for NICKNAME in "${NICKNAMES[@]}"
    do
      # print the PEM from the cert8.db and get the FP with openssl
      FP=$( certutil -L -n "${NICKNAME}" -a -d "${CERT8}" | openssl x509 -noout -fingerprint -sha1 | sed 's/^.*Fingerprint=//' )
      if [ -n "${FP}" ]
      then
	#echo "${NICKNAME}: ${FP}"
	CERT8_CAs["${FP}"]="${NICKNAME}"
	CERT8_NICKS["${NICKNAME}"]="${FP}"
      fi
    done
  done
  echo -e "${#CERT8_CAs[*]} CAs\n"

  return
} # index_cas()

function rename_libnssckbi() {
  #find /usr/{lib,lib64} -name 'libnssckbi.so'
  find /usr/{lib,lib64} -name 'libnssckbi.so' -exec mv -v '{}' '{}.saved' \;
  # this is because:
  # lrwxrwxrwx 1 root root     19 Sep 22 20:27 /usr/lib64/seamonkey-2.29/libnssckbi.so -> libnssckbi.so.saved
  # results into:
  # mv: '/usr/lib64/seamonkey-2.29/libnssckbi.so' and '/usr/lib64/seamonkey-2.29/libnssckbi.so.saved' are the same file
  find /usr/{lib,lib64} -name 'libnssckbi.so' -exec rm -v '{}' \;

  return ${?}
} # rename_libnssckbi()

function usage() {
  cat 0<<-EOF
	${0##*/} OPTIONS ACTION

	options:

	  -p path	path to CertPatrol's DB			(reference)
	  		this constructs the list of required CAs
	  -P path	path to Firefox profile to update	(new profile)
	  -c PEM file	path to single root CA PEM file to import
	  -C		use "basic list" (${#BASIC_LIST[*]} CAs)
	  -d		debug

	  both paths are paths to Firefox's profile directory, e.g. ~/.mozilla/firefox/XXXXXXXX.default

	actions:

	  -a		import	required CAs list
	  -A		print	required CAs list (dry-run)
	  -l		get rid of libnssckbi.so
	  -r		reverse search
	                (list the certs on the file system that are on the cert8.db)
EOF
  return
} # usage()

if [ ${#} -eq 0 ]
then
  usage
  exit
fi

while getopts "dhp:P:c:CaAlr" OPTION
do
  case "${OPTION}" in
    "d") DEBUG=1 ;;
    "h")
      usage
      exit 0
    ;;
    "p")
      OLD_FF_HOME="${OPTARG}"
      CP="${OLD_FF_HOME}/CertPatrol.sqlite"
    ;;
    "P")
      if [ -z "${OPTARG}" -o ! -d "${OPTARG}" ]
      then
        echo "error: -P requires an option!" 1>&2
	exit 1
      fi
      FF_HOME="${OPTARG}"
    ;;
    "c")
      REQUIRED_CAs=( "${OPTARG}" )
    ;;
    "C")
      REQUIRED_CAs=( ${BASIC_LIST[*]/#/\/usr\/share\/ca-certificates\/} )
    ;;
    "a") ACTION="import_cas" ;;
    "A") ACTION="print" ;;
    "l") ACTION="renamelib" ;;
    "r") ACTION="rev" ;;
    *)
      usage
    ;;
  esac
done

if [ ${#REQUIRED_CAs[*]} -eq 0 ]
then
  index_cas
  get_required_cas_list
fi

case "${ACTION}" in
  "import_cas") import_cas ;;
  "print") print_required_cas_list ;;
  "rev") reverse_index ;;
  "renamelib") rename_libnssckbi ;;
  *)
    echo "error: no action defined." 1>&2
    exit 1
  ;;
esac

if [ -n "${FF_HOME}" ]
then
  # list the final result
  CERT_COUNT=$(( $( certutil -L -d "${FF_HOME}" | wc -l ) - 4 ))
  echo -e "\ncurrent root CA list from ${FF_HOME}/cert8.db (${CERT_COUNT} certificates):\n"
  certutil -L -d "${FF_HOME}" | sed 1,4d | grep -v '\(,,\|u,u,u\)'
  echo -e "\ncountries (check the codes from https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2#Officially_assigned_code_elements):\n"
  print_countries
fi
