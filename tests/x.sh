#!/bin/sh

__find_test_dir() {
    local __cmd="$1"
    case "${__cmd}" in
      */*) local __script_path="${__cmd}" ;;
        *) local __script_path=$(command -v "${__cmd}") ;;
    esac

    cd "$(dirname "${__script_path}")" && pwd
}

__tests="$(__find_test_dir "$0")"
__cmd="$1"
find "${__tests}" -maxdepth 2 -mindepth 2 -type f -name "test.sh" -exec {} "$@" \;
