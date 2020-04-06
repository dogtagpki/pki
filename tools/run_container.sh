#!/bin/bash

# This tool attempts to detect the presence of various tools to run the CI
# images. If present, it'll use them to run the specified container image.

function rc_buildah() {
    buildah_path="$(command -v buildah)"
    podman_path="$(command -v podman)"

    [ "x$buildah_path" != "x" ] && [ "x$podman_path" != "x" ]
}

function rc_docker() {
    docker_path="$(command -v docker)"

    [ "x$docker_path" != "x" ]
}

function rc_run() {
    local image="$1"
    local ret=0

    if [ ! -f "tools/Dockerfiles/$image" ]; then
        echo "Error: tools/Dockerfiles/$image is not a file; must be an" 1>&2
        echo "existing location to launch container." 1>&2

        exit 1
    fi

    if rc_buildah; then
        buildah bud --tag "pki_$image:latest" -f "tools/Dockerfiles/$image" .
        ret="$?"
        if [ "x$ret" != "x0" ]; then
            echo "Container build exited with status: $ret"
            return $ret
        fi

        podman run "pki_$image:latest"
        ret="$?"
        if [ "x$ret" != "x0" ]; then
            echo "Container run exited with status: $ret"
            return $ret
        fi
    elif rc_docker; then
        docker build --tag "pki_$image:latest" -f "tools/Dockerfiles/$image" .
        ret="$?"
        if [ "x$ret" != "x0" ]; then
            echo "Container build exited with status: $ret"
            return $ret
        fi

        docker run "pki_$image:latest"
        ret="$?"
        if [ "x$ret" != "x0" ]; then
            echo "Container run exited with status: $ret"
            return $ret
        fi
    else
        echo "No supported container platform; please rerun with podman" 1>&2
        echo "and buildah or docker installed." 1>&2
    fi
}

if [[ "x$1" =~ "help" ]] || [ "x$1" = "x-h" ]; then
    echo "Usage: $0 <image>" 1>&2
    echo "" 1>&2
    echo "Run the container task <image> using buildah+podman or docker" 1>&2
    echo "Note: <image> must be the name of a file located under" 1>&2
    echo "      tools/Dockerfiles in the main repo." 1>&2
    exit 0
fi

rc_run "$1"