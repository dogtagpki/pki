#! /bin/bash -e

SCRIPT_PATH=`readlink -f "$0"`
SCRIPT_NAME=`basename "$SCRIPT_PATH"`

BIN_DIR=`dirname "$SCRIPT_PATH"`
TESTS_DIR=`dirname "$BIN_DIR"`

FLAKE8_CONFIG="$TESTS_DIR/tox.ini"

usage() {
    echo "Usage: $SCRIPT_NAME [OPTIONS]"
    echo
    echo "Options:"
    echo "    --config=<path>        flake8 configuration (default: $FLAKE8_CONFIG)"
    echo " -v,--verbose              Run in verbose mode."
    echo "    --debug                Run in debug mode."
    echo "    --help                 Show help message."
}

while getopts v-: arg ; do
    case $arg in
    v)
        set -x
        ;;
    -)
        LONG_OPTARG="${OPTARG#*=}"

        case $OPTARG in
        config?*)
            FLAKE8_CONFIG="$LONG_OPTARG"
            ;;
        help)
            usage
            exit
            ;;
        '')
            break # "--" terminates argument processing
            ;;
        config*)
            echo "ERROR: Missing argument for --$OPTARG option" >&2
            exit 1
            ;;
        *)
            echo "ERROR: Illegal option --$OPTARG" >&2
            exit 1
            ;;
        esac
        ;;
    \?)
        exit 1 # getopts already reported the illegal option
        ;;
    esac
done

PATHS=`python3 -Ic "import sys; print(' '.join(sys.path))"`
SOURCES=""

for path in $PATHS; do
    if [ -d $path/pki ]; then
        SOURCES="$SOURCES `find $path/pki -name "*.py"`"
    fi
done

SOURCES="$SOURCES `find /usr/share/pki/upgrade -name "*.py"`"
SOURCES="$SOURCES `find /usr/share/pki/server/upgrade -name "*.py"`"

python3-flake8 \
    --config ${FLAKE8_CONFIG} \
    $SOURCES
