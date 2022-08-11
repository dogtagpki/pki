#!/bin/bash

# 0. Globals
## 0.0 Paths

### Absolute path to this script
SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPTPATH="$(dirname "$SCRIPT")"
CERTPATH="$SCRIPTPATH/../resources/certs"
NSSDBPATH="$SCRIPTPATH/../resources/dbs"

### Absolute path to the PKICertImport script.
PCI="/usr/bin/PKICertImport"

## 0.1 Names of Certificates
CA_ROOT="CA Root - A"
CA_SUB="CA Sub - A.A"
CA_SERVER="CA Server - A.B"
CA_SUB_SERVER_A="CA Server - A.A.A"
CA_SUB_SERVER_B="CA Server - A.A.B"

COMP_ROOT="Compromised Root - B"
COMP_SUB="Compromised Sub - B.A"
COMP_SERVER="Compromised Server - B.B"
COMP_SUB_SERVER_A="Compromised Server - B.A.A"
COMP_SUB_SERVER_B="Compromised Server - B.A.B"

SELF_SERVER="Self-Signed Server - C"

## 0.2 Paths to Certificates
P_CA_ROOT="ca_root-a"
P_CA_SUB="ca_sub-a-a"
P_CA_SERVER="sslserver-a-b"
P_CA_SUB_SERVER_A="sslserver-a-a-a"
P_CA_SUB_SERVER_B="sslserver-a-a-b"

P_COMP_ROOT="comp_root-b"
P_COMP_SUB="comp_sub-b.a"
P_COMP_SERVER="sslserver-b-b"
P_COMP_SUB_SERVER_A="sslserver-b-a-a"
P_COMP_SUB_SERVER_B="sslserver-b-a-b"

P_SELF_SERVER="sslserver-c"

## 0.3 Extensions
CERT="crt"
REQ="csr"
PK12="p12"

CA_EXT="ca_signing.conf"
CA_SUB_EXT="ca_sub_signing.conf"
SSL_EXT="sslserver.conf"

## 0.4 Subjects
S_CA_ROOT="CN=CA Root Certificate, OU=pki-tomcat, O=dogtag"
S_CA_SUB="CN=CA Sub Certificate, OU=pki-tomcat, O=dogtag"
S_CA_SERVER="CN=ab.example.com, OU=pki-tomcat, O=dogtag"
S_CA_SUB_SERVER_A="CN=aaa.example.com, OU=pki-tomcat, O=dogtag"
S_CA_SUB_SERVER_B="CN=aab.example.com, OU=pki-tomcat, O=dogtag"

S_COMP_ROOT="CN=Compromised Root Certificate, OU=pki-tomcat, O=dogtag"
S_COMP_SUB="CN=Compromised Sub Certificate, OU=pki-tomcat, O=dogtag"
S_COMP_SERVER="CN=bb.example.com, OU=pki-tomcat, O=dogtag"
S_COMP_SUB_SERVER_A="CN=baa.example.com, OU=pki-tomcat, O=dogtag"
S_COMP_SUB_SERVER_B="CN=bab.example.com, OU=pki-tomcat, O=dogtag"

S_SELF_SERVER="CN=c.example.com, OU=pki-tomcat, O=dogtag"


function __d() {
    local line_number
    line_number="$(caller | awk '{print $1}')"
    local prev_line
    prev_line="$(tail -n "+$(( line_number - 1 ))" "$SCRIPT" | head -n 1)"
    local line
    line="$(tail -n "+$line_number" "$SCRIPT" | head -n 1)"
    local next_line
    next_line="$(tail -n "+$(( line_number + 1 ))" "$SCRIPT" | head -n 1)"

    echo "fail"
    echo "error:" "$@" 1>&2
    echo "        | $(( line_number - 1 )) | $prev_line" 1>&2
    echo "here -> | $line_number | $line" 1>&2
    echo "        | $(( line_number + 1 )) | $next_line" 1>&2
    exit 1
}

function __is_verbose() {
    [ -n "$VERBOSE" ] || [ -n "$TEST_VERBOSE" ]
}

function __v() {
    if __is_verbose; then
        echo "" 1>&2
        echo "::verbose::" "$@" 1>&2
        echo "" 1>&2
    fi
}

function __exec() {
    local command="$1"
    shift

    __v "::exec::" "$command" "$@"

    if __is_verbose; then
        "$command" "$@"
    else
        "$command" "$@" 1>/dev/null 2>/dev/null
    fi
}

function certutil_add() {(
    set -e

    local database="$NSSDBPATH/$1"
    local nickname="$2"
    local file="$CERTPATH/$3.$CERT"
    local mode="$4"

    if [ -z "$mode" ]; then
        mode="server"
    fi

    if [ "$mode" == "server" ]; then
        __exec certutil -A -d "$database" -n "$nickname" -a -i "$file" -t ,,
    elif [ "$mode" == "ca" ]; then
        __exec certutil -A -d "$database" -n "$nickname" -a -i "$file" -t CT,C,C
    else
        __exec certutil -A -d "$database" -n "$nickname" -a -i "$file" -t "$mode"
    fi
)}

function certutil_contains_cert() {(
    set -e

    local database="$NSSDBPATH/$1"
    local nickname="$2"

    # List of known trust flags; combined from man pages and online
    # documentation. Copied from PKICertImport.bash
    local tf="pPcCTuw"

    certutil -L -d "$database" |
        grep "[$tf]*,[$tf]*,[$tf]*" |
        sed "s/[[:space:]]*[$tf]*,[$tf]*,[$tf]*//g" |
        sed "s/[[:space:]]*$//g" |
        sort -u | grep -iq "^$nickname$"
)}

function certutil_contains_num_certs() {(
    set -e

    local database="$NSSDBPATH/$1"
    local count="$2"

    # List of known trust flags; combined from man pages and online
    # documentation. Copied from PKICertImport.bash
    local tf="pPcCTuw"

    actual_count="$(certutil -L -d "$database" |
        grep "[$tf]*,[$tf]*,[$tf]*" |
        sed "s/[[:space:]]*[$tf]*,[$tf]*,[$tf]*//g" |
        sed "s/[[:space:]]*$//g" |
        sort -u | wc -l)"

    if [ -n "$count" ]; then
        (( count == actual_count ))
    else
        return "$actual_count"
    fi
)}

function certutil_contains_num_keys() {(
    set -e

    local database="$NSSDBPATH/$1"
    local count="$2"

    # List of known trust flags; combined from man pages and online
    # documentation. Copied from PKICertImport.bash
    local tf="pPcCTuw"

    actual_count="$(certutil -K -d "$database" |
        grep '^<[[:space:]]*[0-9]*>' |
        sed 's/^<[[:space:]]*[0-9]*>[[:space:]]*rsa//g' |
        sed "s/[[:space:]]*$//g" |
        awk '{print $1}' |
        sort -u | wc -l)"

    if [ -n "$count" ]; then
        (( count == actual_count ))
    else
        return "$actual_count"
    fi
)}

function pci_cert() {(
    set -e

    local database="$NSSDBPATH/$1"
    local nickname="$2"
    local file="$CERTPATH/$3.$CERT"
    local mode="$4"
    local usage="$5"
    shift 4

    if [ "$mode" == "server" ]; then
        mode=",,"
        usage="V"
    elif [ "$mode" == "ca" ]; then
        mode="CT,C,C"
        usage="L"
    else
        shift
    fi

    __exec bash $PCI -d "$database" -n "$nickname" -a -i "$file" -t "$mode" -u "$usage" "$@"
)}

function pci_chain() {(
    set -e

    local database="$NSSDBPATH/$1"
    local pass="$database/password.txt"
    local nickname="$2"
    local file="$CERTPATH/$3.$PK12"
    shift 3

    local mode="$1"
    local usage="$2"
    shift

    if [ "$mode" == "server" ]; then
        mode=",,"
        usage="V"
    elif [ "$mode" == "ca" ]; then
        mode="CT,C,C"
        usage="L"
    else
        shift
    fi

    local chain_mode="$1"
    local chain_usage="$2"
    shift

    if [ "$chain_mode" == "server" ]; then
        chain_mode=",,"
        chain_usage="V"
    elif [ "$chain_mode" == "ca" ]; then
        chain_mode="CT,C,C"
        chain_usage="L"
    else
        shift
    fi

    __exec bash $PCI -d "$database" -n "$nickname" -i "$file" -t "$mode" -u "$usage" --pkcs12 --chain --chain-trust "$chain_mode" --chain-usage "$chain_usage" "$@" --pkcs12-password "$pass" --password "$pass"
)}

function pci_leaf() {(
    set -e

    local database="$NSSDBPATH/$1"
    local pass="$database/password.txt"
    local nickname="$2"
    local file="$CERTPATH/$3.$PK12"
    shift 3

    local mode="$1"
    local usage="$2"
    shift

    if [ "$mode" == "server" ]; then
        mode=",,"
        usage="V"
    elif [ "$mode" == "ca" ]; then
        mode="CT,C,C"
        usage="L"
    else
        shift
    fi

    __exec bash $PCI -d "$database" -n "$nickname" -i "$file" -t "$mode" -u "$usage" --pkcs12 --leaf-only "$@" --pkcs12-password "$pass" --password "$pass"
)}

function create_nssdb() {(
    set -e

    local name="$1"
    local copy_root="$2"
    local copy_sub="$3"

    local new_db="$NSSDBPATH/$name"

    rm -rf "$new_db"
    mkdir -p "$new_db"
    echo "" > "$new_db/password.txt"

    __exec certutil -N -d "$new_db" --empty-password

    if [ -n "$copy_root" ] && [ "x$copy_root" != "xfalse" ]; then
        certutil_add "$name" "$CA_ROOT" "$P_CA_ROOT" ca
    fi

    if [ -n "$copy_sub" ] && [ "x$copy_sub" != "xfalse" ]; then
        certutil_add "$name" "$CA_SUB" "$P_CA_SUB" ca
    fi
)}

function create_certificate(){

    local db=$1
    local ext=$2
    local filename=$3
    local subject=$4
    local name=$5
    local password=$6
    local issuer=$7

    __exec pki -d "$db" nss-cert-request --ext "$ext" --key-size 4096 --csr "$filename.$REQ" --subject "$subject" || __d "Cannot create $name csr"

    if [ -n "$issuer" ]; then
    __exec pki -d "$db" nss-cert-issue --ext "$ext" --csr "$filename.$REQ" --cert "$filename.$CERT" --issuer "$issuer" || __d "Cannot issue $name"
    else
    __exec pki -d "$db" nss-cert-issue --ext "$ext" --csr "$filename.$REQ" --cert "$filename.$CERT" || __d "Cannot issue $name"
    fi
    __exec pki -d "$db" nss-cert-import --cert "$filename.$CERT" "$name" || __d "Cannot import $name"
    __exec pki -d "$db" pkcs12-export --pkcs12 "$filename.$PK12" --password-file "$password" "$name" || __d "Cannot export p12 for $name"

}

function generate_certificates() {
    local db="${NSSDBPATH}/global"
    local pass="$db/password.txt"

    rm -rf "$db"
    rm -rf "$CERTPATH/*.$CERT"
    rm -rf "$CERTPATH/*.$REQ"
    rm -rf "$CERTPATH/*.$PK12"

    __exec pki -d "$db" nss-create || __d "Global db error"
    echo "" > "$pass"

    # Root CA
    create_certificate "$db" "$CERTPATH/$CA_EXT" "$CERTPATH/$P_CA_ROOT" "$S_CA_ROOT" "$CA_ROOT" "$pass"
    create_certificate "$db" "$CERTPATH/$CA_EXT" "$CERTPATH/$P_COMP_ROOT" "$S_COMP_ROOT" "$COMP_ROOT" "$pass"

    # Sub CA
    create_certificate "$db" "$CERTPATH/$CA_SUB_EXT" "$CERTPATH/$P_CA_SUB" "$S_CA_SUB" "$CA_SUB" "$pass" "$CA_ROOT"
    create_certificate "$db" "$CERTPATH/$CA_SUB_EXT" "$CERTPATH/$P_COMP_SUB" "$S_COMP_SUB" "$COMP_SUB" "$pass" "$COMP_ROOT"

    # Server
    create_certificate "$db" "$CERTPATH/$SSL_EXT" "$CERTPATH/$P_CA_SERVER" "$S_CA_SERVER" "$CA_SERVER" "$pass" "$CA_ROOT"
    create_certificate "$db" "$CERTPATH/$SSL_EXT" "$CERTPATH/$P_COMP_SERVER" "$S_COMP_SERVER" "$COMP_SERVER" "$pass" "$COMP_ROOT"

    # Sub Server a
    create_certificate "$db" "$CERTPATH/$SSL_EXT" "$CERTPATH/$P_CA_SUB_SERVER_A" "$S_CA_SUB_SERVER_A" "$CA_SUB_SERVER_A" "$pass" "$CA_SUB"
    create_certificate "$db" "$CERTPATH/$SSL_EXT" "$CERTPATH/$P_COMP_SUB_SERVER_A" "$S_COMP_SUB_SERVER_A" "$COMP_SUB_SERVER_A" "$pass" "$COMP_SUB"

    # Sub Server b
    create_certificate "$db" "$CERTPATH/$SSL_EXT" "$CERTPATH/$P_CA_SUB_SERVER_B" "$S_CA_SUB_SERVER_B" "$CA_SUB_SERVER_B" "$pass" "$CA_SUB"
    create_certificate "$db" "$CERTPATH/$SSL_EXT" "$CERTPATH/$P_COMP_SUB_SERVER_B" "$S_COMP_SUB_SERVER_B" "$COMP_SUB_SERVER_B" "$pass" "$COMP_SUB"

    # Sub Server b
    create_certificate "$db" "$CERTPATH/$SSL_EXT" "$CERTPATH/$P_SELF_SERVER" "$S_SELF_SERVER" "$SELF_SERVER" "$pass"
}

function test_cert_import_root() {
    local db="test_cert_import_server"
    echo -n "$db... "

    create_nssdb "$db" || __d "Unable to create nssdb: $db"

    certutil_contains_cert "$db" "$CA_ROOT" && __d "$db should not contain $CA_ROOT"
    pci_cert "$db" "$CA_ROOT" "$P_CA_ROOT" ca
    certutil_contains_cert "$db" "$CA_ROOT" || __d "$db should contain $CA_ROOT"

    certutil_contains_cert "$db" "$COMP_ROOT" && __d "$db should not contain $COMP_ROOT"
    pci_cert "$db" "$COMP_ROOT" "$P_COMP_ROOT" ca
    certutil_contains_cert "$db" "$COMP_ROOT" || __d "$db should contain $COMP_ROOT"

    echo "pass"
}

function test_cert_import_server() {
    local db="${FUNCNAME[0]}"
    echo -n "$db... "

    create_nssdb "$db" root sub
    certutil_contains_cert "$db" "$CA_ROOT" || __d "$db should contain $CA_ROOT"
    certutil_contains_cert "$db" "$CA_SUB" || __d "$db should contain $CA_SUB"

    certutil_contains_cert "$db" "$CA_SERVER" && __d "$db should not contain $CA_SERVER"
    pci_cert "$db" "$CA_SERVER" "$P_CA_SERVER" server
    certutil_contains_cert "$db" "$CA_SERVER" || __d "$db should contain $CA_SERVER"

    certutil_contains_cert "$db" "$CA_SUB_SERVER_A" && __d "$db should not contain $CA_SUB_SERVER_A"
    pci_cert "$db" "$CA_SUB_SERVER_A" "$P_CA_SUB_SERVER_A" server
    certutil_contains_cert "$db" "$CA_SUB_SERVER_A" || __d "$db should contain $CA_SUB_SERVER_A"

    certutil_contains_cert "$db" "$CA_SUB_SERVER_B" && __d "$db should not contain $CA_SUB_SERVER_B"
    pci_cert "$db" "$CA_SUB_SERVER_B" "$P_CA_SUB_SERVER_B" server
    certutil_contains_cert "$db" "$CA_SUB_SERVER_B" || __d "$db should contain $CA_SUB_SERVER_B"

    echo "pass"
}

function test_cert_missing_intermediate() {
    local db="${FUNCNAME[0]}"
    echo -n "$db... "

    create_nssdb "$db" root
    certutil_contains_cert "$db" "$CA_ROOT" || __d "$db should contain $CA_ROOT"
    certutil_contains_cert "$db" "$CA_SUB" && __d "$db should not contain $CA_SUB"

    certutil_contains_cert "$db" "$CA_SUB_SERVER_A" && __d "$db should not contain $CA_SUB_SERVER_A"
    pci_cert "$db" "$CA_SUB_SERVER_A" "$P_CA_SUB_SERVER_A" server
    certutil_contains_cert "$db" "$CA_SUB_SERVER_A" && __d "$db should not contain $CA_SUB_SERVER_A"

    certutil_contains_cert "$db" "$CA_SUB_SERVER_B" && __d "$db should not contain $CA_SUB_SERVER_B"
    pci_cert "$db" "$CA_SUB_SERVER_B" "$P_CA_SUB_SERVER_B" server
    certutil_contains_cert "$db" "$CA_SUB_SERVER_B" && __d "$db should not contain $CA_SUB_SERVER_B"

    echo "pass"
}

function test_chain_unsafe_trust_then_verify() {
    local db="${FUNCNAME[0]}"
    echo -n "$db... "

    create_nssdb "$db"
    certutil_contains_cert "$db" "$CA_ROOT" && __d "$db should not contain $CA_ROOT"
    certutil_contains_cert "$db" "$CA_SUB" && __d "$db should not contain $CA_SUB"

    certutil_contains_cert "$db" "$CA_SUB_SERVER_A" && __d "$db should not contain $CA_SUB_SERVER_A"
    pci_chain "$db" "$CA_SUB_SERVER_A" "$P_CA_SUB_SERVER_A" server ca --unsafe-trust-then-verify || __d "Unexpected error with import operation for $CA_SUB_SERVER_A"

    certutil_contains_cert "$db" "$CA_ROOT" || __d "$db should contain $CA_ROOT"
    certutil_contains_cert "$db" "$CA_SUB" || __d "$db should contain $CA_SUB"
    certutil_contains_cert "$db" "$CA_SUB_SERVER_A" || __d "$db should contain $CA_SUB_SERVER_A"

    certutil_contains_num_certs "$db" 3 || __d "$db should contain three certificates but contained:" "$(certutil_contains_num_certs "$db"; echo $?)"
    certutil_contains_num_keys "$db" 1 || __d "$db should contain one key but contained:" "$(certutil_contains_num_keys "$db"; echo $?)"

    echo "pass"
}

function test_chain_fail_no_root() {
    local db="${FUNCNAME[0]}"
    echo -n "$db... "

    create_nssdb "$db"
    certutil_contains_cert "$db" "$CA_ROOT" && __d "$db should not contain $CA_ROOT"
    certutil_contains_cert "$db" "$CA_SUB" && __d "$db should not contain $CA_SUB"

    certutil_contains_cert "$db" "$CA_SERVER" && __d "$db should not contain $CA_SERVER"
    pci_chain "$db" "$CA_SERVER" "$P_CA_SERVER" server ca && __d "Unexpected success for $CA_SERVER"
    certutil_contains_cert "$db" "$CA_SERVER" && __d "$db should not contain $CA_SERVER"

    certutil_contains_cert "$db" "$CA_SUB_SERVER_A" && __d "$db should not contain $CA_SUB_SERVER_A"
    pci_chain "$db" "$CA_SUB_SERVER_A" "$P_CA_SUB_SERVER_A" server ca && __d "Unexpected success for $CA_SUB_SERVER_A"
    certutil_contains_cert "$db" "$CA_SUB_SERVER_A" && __d "$db should not contain $CA_SUB_SERVER_A"

    certutil_contains_cert "$db" "$CA_SUB_SERVER_B" && __d "$db should not contain $CA_SUB_SERVER_B"
    pci_chain "$db" "$CA_SUB_SERVER_B" "$P_CA_SUB_SERVER_B" server ca && __d "Unexpected success for $CA_SUB_SERVER_B"
    certutil_contains_cert "$db" "$CA_SUB_SERVER_B" && __d "$db should not contain $CA_SUB_SERVER_B"

    certutil_contains_num_certs "$db" 0 || __d "$db should contain no certificates but contained:" "$(certutil_contains_num_certs "$db"; echo $?)"
    certutil_contains_num_keys "$db" 0 || __d "$db should contain no keys but contained:" "$(certutil_contains_num_keys "$db"; echo $?)"

    echo "pass"
}

function test_chain_import() {
    local db="${FUNCNAME[0]}"
    echo -n "$db... "

    create_nssdb "$db" root
    certutil_contains_cert "$db" "$CA_ROOT" || __d "$db should contain $CA_ROOT"
    certutil_contains_cert "$db" "$CA_SUB" && __d "$db should not contain $CA_SUB"

    certutil_contains_cert "$db" "$CA_SERVER" && __d "$db should not contain $CA_SERVER"
    pci_chain "$db" "$CA_SERVER" "$P_CA_SERVER" server ca || __d "Unexpected failure for $CA_SERVER"
    certutil_contains_cert "$db" "$CA_SERVER" || __d "$db should contain $CA_SERVER"

    certutil_contains_cert "$db" "$CA_SUB_SERVER_A" && __d "$db should not contain $CA_SUB_SERVER_A"
    pci_chain "$db" "$CA_SUB_SERVER_A" "$P_CA_SUB_SERVER_A" server ca || __d "Unexpected failure for $CA_SUB_SERVER_A"
    certutil_contains_cert "$db" "$CA_SUB" || __d "$db should contain $CA_SUB"
    certutil_contains_cert "$db" "$CA_SUB_SERVER_A" || __d "$db should contain $CA_SUB_SERVER_A"

    certutil_contains_cert "$db" "$CA_SUB_SERVER_B" && __d "$db should not contain $CA_SUB_SERVER_B"
    pci_chain "$db" "$CA_SUB_SERVER_B" "$P_CA_SUB_SERVER_B" server ca || __d "Unexpected failure for $CA_SUB_SERVER_B"
    certutil_contains_cert "$db" "$CA_SUB_SERVER_B" || __d "$db should contain $CA_SUB_SERVER_B"

    certutil_contains_num_certs "$db" 5 || __d "$db should contain five certificates but contained:" "$(certutil_contains_num_certs "$db"; echo $?)"
    certutil_contains_num_keys "$db" 3 || __d "$db should contain three keys but contained:" "$(certutil_contains_num_keys "$db"; echo $?)"

    echo "pass"
}

function test_leaf_import() {
    local db="${FUNCNAME[0]}"
    echo -n "$db... "

    create_nssdb "$db" root sub
    certutil_contains_cert "$db" "$CA_ROOT" || __d "$db should contain $CA_ROOT"
    certutil_contains_cert "$db" "$CA_SUB" || __d "$db should contain $CA_SUB"

    certutil_contains_cert "$db" "$CA_SERVER" && __d "$db should not contain $CA_SERVER"
    pci_leaf "$db" "$CA_SERVER" "$P_CA_SERVER" server || __d "Unexpected failure for $CA_SERVER"
    certutil_contains_cert "$db" "$CA_SERVER" || __d "$db should contain $CA_SERVER"

    certutil_contains_cert "$db" "$CA_SUB_SERVER_A" && __d "$db should not contain $CA_SUB_SERVER_A"
    pci_leaf "$db" "$CA_SUB_SERVER_A" "$P_CA_SUB_SERVER_A" server || __d "Unexpected failure for $CA_SUB_SERVER_A"
    certutil_contains_cert "$db" "$CA_SUB_SERVER_A" || __d "$db should contain $CA_SUB_SERVER_A"

    certutil_contains_cert "$db" "$CA_SUB_SERVER_B" && __d "$db should not contain $CA_SUB_SERVER_B"
    pci_leaf "$db" "$CA_SUB_SERVER_B" "$P_CA_SUB_SERVER_B" server || __d "Unexpected failure for $CA_SUB_SERVER_B"
    certutil_contains_cert "$db" "$CA_SUB_SERVER_B" || __d "$db should contain $CA_SUB_SERVER_B"

    certutil_contains_num_certs "$db" 5 || __d "$db should contain five certificates but contained:" "$(certutil_contains_num_certs "$db"; echo $?)"
    certutil_contains_num_keys "$db" 3 || __d "$db should contain three keys but contained:" "$(certutil_contains_num_keys "$db"; echo $?)"

    echo "pass"
}

function test_leaf_fail_no_root() {
    local db="${FUNCNAME[0]}"
    echo -n "$db... "

    create_nssdb "$db"
    certutil_contains_cert "$db" "$CA_ROOT" && __d "$db should not contain $CA_ROOT"
    certutil_contains_cert "$db" "$CA_SUB" && __d "$db should not contain $CA_SUB"

    certutil_contains_cert "$db" "$CA_SERVER" && __d "$db should not contain $CA_SERVER"
    pci_leaf "$db" "$CA_SERVER" "$P_CA_SERVER" server && __d "Unexpected success for $CA_SERVER"
    certutil_contains_cert "$db" "$CA_SERVER" && __d "$db should not contain $CA_SERVER"

    certutil_contains_cert "$db" "$CA_SUB_SERVER_A" && __d "$db should not contain $CA_SUB_SERVER_A"
    pci_leaf "$db" "$CA_SUB_SERVER_A" "$P_CA_SUB_SERVER_A" server && __d "Unexpected success for $CA_SUB_SERVER_A"
    certutil_contains_cert "$db" "$CA_SUB_SERVER_A" && __d "$db should not contain $CA_SUB_SERVER_A"

    certutil_contains_cert "$db" "$CA_SUB_SERVER_B" && __d "$db should not contain $CA_SUB_SERVER_B"
    pci_leaf "$db" "$CA_SUB_SERVER_B" "$P_CA_SUB_SERVER_B" server && __d "Unexpected success for $CA_SUB_SERVER_B"
    certutil_contains_cert "$db" "$CA_SUB_SERVER_B" && __d "$db should not contain $CA_SUB_SERVER_B"

    certutil_contains_num_certs "$db" 0 || __d "$db should contain no certificates but contained:" "$(certutil_contains_num_certs "$db"; echo $?)"
    certutil_contains_num_keys "$db" 0 || __d "$db should contain no keys but contained:" "$(certutil_contains_num_keys "$db"; echo $?)"

    echo "pass"
}

function main() {
    time (
        generate_certificates || exit "$Z"
        test_cert_import_root || exit $?
        test_cert_import_server || exit $?
        test_cert_missing_intermediate || exit $?

        test_chain_unsafe_trust_then_verify || exit $?
        test_chain_fail_no_root || exit $?
        test_chain_import || exit $?

        test_leaf_import || exit $?
        test_leaf_fail_no_root || exit $?
    )
}

main
