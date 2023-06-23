#!/bin/sh

VERSION=`jq -r '.dependencies.jquery' package.json | sed "s/\^//"`

cp node_modules/jquery/dist/jquery.min.js \
    base/server-webapp/webapps/ROOT/jquery-$VERSION/jquery.min.js
