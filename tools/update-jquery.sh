#!/bin/sh

VERSION=`jq -r '.dependencies.jquery' package.json | sed "s/\^//"`

cp node_modules/jquery/dist/jquery.min.js \
    base/acme/webapps/acme/js/jquery-$VERSION.js
