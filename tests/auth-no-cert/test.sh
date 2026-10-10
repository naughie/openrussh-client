#!/bin/sh

__proj_id="openrussh-client"
__test_id="auth-no-cert"

__docker_image="${__proj_id}/tests/${__test_id}"

__find_root_dir() {
    local __cmd="$1"
    case "${__cmd}" in
      */*) local __script_path="${__cmd}" ;;
        *) local __script_path=$(command -v "${__cmd}") ;;
    esac

    local __script_dir="$(cd "$(dirname "${__script_path}")" && pwd)"
    dirname "$(dirname "${__script_dir}")"
}

__build_image() {
    docker build -t "${__docker_image}" -f "./tests/${__test_id}/docker/Dockerfile" .
}

__run_image() {
    docker run --rm -it "${__docker_image}"
}


__root_dir="$(__find_root_dir "$0")"
cd "${__root_dir}"

__cmd="$1"
if [ -z "${__cmd}" ]; then
    __build_image
    __run_image
else
    case "$__cmd" in
        build)
            __build_image
            ;;
        run)
            __run_image
            ;;
        *)
            printf 'Usage: %s [build|run]\n' "$0"
            exit 1
            ;;
    esac
fi
