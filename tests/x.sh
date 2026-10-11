#!/bin/sh

__proj_id="openrussh-client"

__find_root_dir() {
    local __cmd="$1"
    case "${__cmd}" in
      */*) local __script_path="${__cmd}" ;;
        *) local __script_path=$(command -v "${__cmd}") ;;
    esac

    local __script_dir="$(cd "$(dirname "${__script_path}")" && pwd)"
    dirname "${__script_dir}"
}

__build_image() {
    docker build -t "${__docker_image}" -f "${__dockerfile}" "${__docker_ctx}" </dev/tty >/dev/tty 2>&1
}

__run_image() {
    docker run --rm -it "${__docker_image}" </dev/tty >/dev/tty 2>&1
}


__repo_root="$(__find_root_dir "$0")"
__cmd="$1"

find "${__repo_root}/tests"/* -prune -type d ! -name "target"  | while IFS= read -r __dir; do
    __dockerfile="${__dir}/docker/Dockerfile"

    if [ -f "${__dockerfile}" ]; then
        __docker_image="${__proj_id}/${__dir#"${__repo_root}"/}"
        __docker_ctx="${__repo_root}"

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
                    printf 'Usage: %s [build|run]\n' "$0"
                    exit 1
                    ;;
            esac
        fi
    fi
done
