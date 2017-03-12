#!/bin/bash
# Generate 'What does it do' README section
# https://github.com/pyllyukko/user.js/
# License: MIT

# Abort on error
set -o errexit

###################################

# Configuration:
# Text used to generate/replace subsection headers

SECTION_HTML5_ID='HTML5/DOM APIs'
SECTION_HTML5_MDOWN="Disable HTML5/DOM media/p2p/geo/sensors/... [APIs](https://wiki.mozilla.org/WebAPI)."

SECTION_MISC_ID='Misc'
SECTION_MISC_MDOWN="Settings that do not belong to other sections or are user specific preferences."

SECTION_EXTENSIONS_ID='Extensions / plugins'
SECTION_EXTENSIONS_MDOWN="Harden preferences related to external plugins (Adobe Flash, Microsoft Silverlight, OpenH264, Java ...)"

SECTION_FEATURES_ID='Firefox (anti-)features / components'
SECTION_FEATURES_MDOWN="Disable Firefox integrated metrics/reporting/experiments, disable potentially insecure/invasive/[undesirable](https://en.wikipedia.org/wiki/Feature_creep) features (PDF reader, New Tab Page, UI tour...), enable Tracking Protection."

SECTION_AUTOCONNECT_ID='Automatic connections'
SECTION_AUTOCONNECT_MDOWN="Prevents the browser from auto-connecting to some Mozilla services, and from predictively opening connections to websites during browsing."

SECTION_HTTP_ID='HTTP'
SECTION_HTTP_MDOWN="HTTP (plain text connection) security related entries. This affects cookies, the user agent, referer and others."

SECTION_CACHING_ID='Caching'
SECTION_CACHING_MDOWN="Enable and configure private browsing mode, don't store information locally during the browsing session (history/caches/downloads/passwords...)"

SECTION_UI_ID='UI related'
SECTION_UI_MDOWN="Improve visibility of security-related elements, mitigate shoulder-surfing"

SECTION_CRYPTO_ID='Cryptography'
SECTION_CRYPTO_MDOWN="Enforce strong cryptography where possible, enable additional cryptography mechanisms ([SSL/TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security), [HTTPS](https://en.wikipedia.org/wiki/HTTPS), [OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol), [HSTS](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security), [HPKP](https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning) ...)"

SECTION_CIPHERS_ID='Ciphers'
SECTION_CIPHERS_MDOWN="Disable known [weak](https://weakdh.org/) ciphers, enforce ciphers with [Forward Secrecy](https://en.wikipedia.org/wiki/Forward_secrecy). Since Firefox 32 most of the weak ciphers are removed which makes most of the changes obsolete and are only persistent in case of you use an outdated release https://bugzilla.mozilla.org/show_bug.cgi?id=934663"

###################################

function _gen_entries() {
    # generate the "What does it do" README section from user.js PREF/SECTION fields and adjacent links
    egrep --line-number "SECTION\:|PREF\:" user.js | egrep -v '\(disabled\)' | sed -e 's/  \+\*//g' | \
    while read LINE; do
        LINENUM=$(echo "$LINE" | awk -F ':' '{ print $1 }')
        LINETYPE=$(echo "$LINE" | awk -F '[:/\*\ ]*' '{ print $2 }' 2>/dev/null)
        LINENAME=$(echo "$LINE" | sed -e 's/.*PREF\: //g; s/.*SECTION\: //g')
        if [ "$LINETYPE" = "SECTION" ]; then
            INDENT=''
            REF_LIST=''
            LINENAME=$(_gen_section_header "$LINENAME")
        else #if $LINETYPE = PREF
            # Build a list of reference links
            REF_LINE=$(( $LINENUM + 1 ))
            REF_NUMBER=1
            REF_LIST=''
            # while next lines start with 'http', generate markdown links and append them to the list
            while sed "${REF_LINE}q;d" user.js | egrep "^// http" >/dev/null; do
                REF_URL=$(sed "${REF_LINE}q;d" user.js | cut -c4-) # 
                REF_MD_LINK="[${REF_NUMBER}](${REF_URL}) "
                REF_LINE=$(( $REF_LINE + 1 ))
                REF_NUMBER=$(( $REF_NUMBER + 1 ))
                REF_LIST="${REF_LIST}${REF_MD_LINK}"
            done
            # if references list is not empty, add decoration chars [ ]
            if [ ! "$REF_LIST" = "" ]; then
                REF_LIST=" [ ${REF_LIST}]"
            fi
            INDENT=' * '; SECTIONDESC=''
        fi
        MARKDOWNLINE="${INDENT}${LINENAME}${REF_LIST}"
        echo "$MARKDOWNLINE"
    done
}

function _gen_section_header() {
    # generate section headers from a predefined list
    # replace section headers extracted from user.js with more detailed descriptions
    # in markdown format (configurable above)
    SECTION_NAME="$@"
    case "$SECTION_NAME" in
    "$SECTION_HTML5_ID")        echo -e "\n### ${SECTION_HTML5_ID}\n\n${SECTION_HTML5_MDOWN}\n" ;;
    "$SECTION_MISC_ID")         echo -e "\n### ${SECTION_MISC_ID}\n\n${SECTION_MISC_MDOWN}\n" ;;
    "$SECTION_EXTENSIONS_ID")   echo -e "\n### ${SECTION_EXTENSIONS_ID}\n\n${SECTION_EXTENSIONS_MDOWN}\n" ;;
    "$SECTION_FEATURES_ID")     echo -e "\n### ${SECTION_FEATURES_ID}\n\n${SECTION_FEATURES_MDOWN}\n" ;;
    "$SECTION_AUTOCONNECT_ID")  echo -e "\n### ${SECTION_AUTOCONNECT_ID}\n\n${SECTION_AUTOCONNECT_MDOWN}\n" ;;
    "$SECTION_HTTP_ID")         echo -e "\n### ${SECTION_HTTP_ID}\n\n${SECTION_HTTP_MDOWN}\n" ;;
    "$SECTION_CACHING_ID")      echo -e "\n### ${SECTION_CACHING_ID}\n\n${SECTION_CACHING_MDOWN}\n" ;;
    "$SECTION_UI_ID")           echo -e "\n### ${SECTION_UI_ID}\n\n${SECTION_UI_MDOWN}\n" ;;
    "$SECTION_CRYPTO_ID")       echo -e "\n### ${SECTION_CRYPTO_ID}\n\n${SECTION_CRYPTO_MDOWN}\n" ;;
    "$SECTION_CIPHERS_ID")      echo -e "\n### ${SECTION_CIPHERS_ID}\n\n${SECTION_CIPHERS_MDOWN}\n" ;;
    "*")                        echo -e "ERROR: unsupported section $SECTION_NAME"; exit 1 ;;
    esac
}

function _write_readme() {
    # write the generated section to README.md (section delimited by html comments BEGIN/END SECTION)
    # https://stackoverflow.com/questions/21876431
    echo "$README_SECTION" > whatdoesitdo.tmp.md
    awk '
    BEGIN               {p=1}
    /BEGIN SECTION/   {print;system("cat whatdoesitdo.tmp.md");p=0}
    /END SECTION/     {p=1}
    p' README.md > README-new.md
    mv README-new.md README.md
    rm whatdoesitdo.tmp.md

    #sed --silent "/BEGIN SECTION/{:a;N;/END SECTION/!ba;N;s/.*\n${README_SECTION}\n/};p" README.md
}

###################################

README_SECTION=$(_gen_entries)
_write_readme
