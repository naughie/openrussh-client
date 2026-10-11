#!/bin/sh

set -e

__proj_id="openrussh-client"

__print_usage() {
    printf 'Usage: %s [test_id] [build|run]\n' "${__script}" >&2
    exit 1
}

__find_root_dir() {
    case "${__script}" in
      */*) local __script_path="${__script}" ;;
        *) local __script_path=$(command -v "${__script}") ;;
    esac

    local __script_dir="$(cd "$(dirname "${__script_path}")" && pwd)"
    dirname "${__script_dir}"
}

__build_image() {
    docker build -t "${__docker_image}" -f "${__dockerfile}" "${__docker_ctx}"
}

__run_image() {
    if [ "${__tty}" = true ]; then
        docker run --rm -t "${__docker_image}"
    else
        docker run --rm -a stdout -a stderr "${__docker_image}"
    fi
}

__x() {
    if [ -f "${__dockerfile}" ]; then
        if [ -z "${__cmd}" ]; then
            __build_image
            __run_image
        else
            case "${__cmd}" in
                build)
                    __build_image
                    ;;
                run)
                    __run_image
                    ;;
                *)
                    __print_usage
                    ;;
            esac
        fi
    fi
}


__script="$0"

__arg1="${1-}"
__arg2="${2-}"

__repo_root="$(__find_root_dir)"

case "$#" in
    0)
        __single_test=false
        ;;
    1)
        case "${__arg1}" in
            run|build) __single_test=false ;;
                    *)
                        if [ -d "${__repo_root}/tests/${__arg1}" ]; then
                            __single_test=true
                        else
                            __print_usage
                        fi
                        ;;
        esac
        ;;
    2)
        case "${__arg2}" in
            run|build)
                if [ -d "${__repo_root}/tests/${__arg1}" ]; then
                    __single_test=true
                else
                    __print_usage
                fi
                ;;
            *)
                __print_usage
                ;;
        esac
        ;;
    *)
        __print_usage
        ;;
esac

if [ "${__single_test}" = true ]; then
    __test_id="${__arg1}"
    __cmd="${__arg2}"
else
    __cmd="${__arg1}"
fi

__tty=false
if ( : </dev/tty >/dev/tty ) 2>/dev/null; then
    __tty=true
fi

{
    if [ "${__single_test}" = true ]; then
        find "${__repo_root}/tests/${__test_id}" -prune -type d
    else
        find "${__repo_root}/tests"/* -prune -type d ! -name "target"
    fi
} | while IFS= read -r __dir; do
    __dockerfile="${__dir}/docker/Dockerfile"
    __docker_image="${__proj_id}/${__dir#"${__repo_root}"/}"
    __docker_ctx="${__repo_root}"

    set +e
    if [ "${__tty}" = true ]; then
        __x </dev/tty >/dev/tty 2>&1
    else
        __x
    fi
    set -e
done
