#!/usr/bin/env bash

POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
  case $1 in
    --tech)
      TECH="$2"
      shift # past argument
      shift # past value
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

if [ "$TECH" = "java" || "$TECH" = "csharp" || "$TECH" = "python" ]; then
    echo "TECH can only be java or csharp or python"
    exit 1
fi

entry_point=$1
cd $entry_point

result_filename="codeql.sarif"

if command -v codeql &> /dev/null; then
    echo "Using system installation of CodeQL" >&2
    CODEQL=codeql
else
    if ! [ -f $HOME/.bentoo/codeql/codeql ]; then
        echo "Downloading CodeQL" >&2
        rm codeql-bundle-linux64.tar.gz
        wget "https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.17.3/codeql-bundle-linux64.tar.gz" >&2
        mkdir -p $HOME/.bentoo >&2
        tar -xvzf codeql-bundle-linux64.tar.gz --directory $HOME/.bentoo/ >&2
        rm codeql-bundle-linux64.tar.gz >&2
    fi
    echo "Using downloaded CodeQL" >&2
    CODEQL=$HOME/.bentoo/codeql/codeql
fi


$CODEQL database create codeql_db --language=$TECH >&2
$CODEQL database upgrade codeql_db >&2
$CODEQL database analyze codeql_db $TECH-security-and-quality.qls --format=sarif-latest --output=$result_filename >&2

cat $result_filename
