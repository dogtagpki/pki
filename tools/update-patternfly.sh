#!/bin/sh

VERSION=`jq -r '.dependencies."@patternfly/patternfly"' package.json | sed "s/\^//"`

cp node_modules/@patternfly/patternfly/patternfly.min.css \
    base/acme/webapps/acme/css/patternfly-$VERSION.css
cp node_modules/@patternfly/patternfly/patternfly.min.css.map \
    base/acme/webapps/acme/css/patternfly.min.css.map

cp node_modules/@patternfly/patternfly/assets/fonts/RedHatDisplay/RedHatDisplay-Medium.woff \
    base/acme/webapps/acme/css/assets/fonts/RedHatDisplay
cp node_modules/@patternfly/patternfly/assets/fonts/RedHatText/RedHatText-Medium.woff \
    base/acme/webapps/acme/css/assets/fonts/RedHatText
cp node_modules/@patternfly/patternfly/assets/fonts/RedHatText/RedHatText-Regular.woff \
    base/acme/webapps/acme/css/assets/fonts/RedHatText
cp node_modules/@patternfly/patternfly/assets/fonts/overpass-webfont/overpass-bold.ttf \
    base/acme/webapps/acme/css/assets/fonts/overpass-webfont
cp node_modules/@patternfly/patternfly/assets/fonts/overpass-webfont/overpass-bold.woff \
    base/acme/webapps/acme/css/assets/fonts/overpass-webfont
cp node_modules/@patternfly/patternfly/assets/fonts/overpass-webfont/overpass-bold.woff2 \
    base/acme/webapps/acme/css/assets/fonts/overpass-webfont
cp node_modules/@patternfly/patternfly/assets/fonts/overpass-webfont/overpass-light.ttf \
    base/acme/webapps/acme/css/assets/fonts/overpass-webfont
cp node_modules/@patternfly/patternfly/assets/fonts/overpass-webfont/overpass-light.woff \
    base/acme/webapps/acme/css/assets/fonts/overpass-webfont
cp node_modules/@patternfly/patternfly/assets/fonts/overpass-webfont/overpass-light.woff2 \
    base/acme/webapps/acme/css/assets/fonts/overpass-webfont
cp node_modules/@patternfly/patternfly/assets/fonts/webfonts/fa-solid-900.ttf \
    base/acme/webapps/acme/css/assets/fonts/webfonts
cp node_modules/@patternfly/patternfly/assets/fonts/webfonts/fa-solid-900.woff \
    base/acme/webapps/acme/css/assets/fonts/webfonts
cp node_modules/@patternfly/patternfly/assets/fonts/webfonts/fa-solid-900.woff2 \
    base/acme/webapps/acme/css/assets/fonts/webfonts
cp node_modules/@patternfly/patternfly/assets/images/img_avatar.svg \
    base/acme/webapps/acme/css/assets/images
cp node_modules/@patternfly/patternfly/assets/pficon/pficon.ttf \
    base/acme/webapps/acme/css/assets/pficon
cp node_modules/@patternfly/patternfly/assets/pficon/pficon.woff \
    base/acme/webapps/acme/css/assets/pficon
cp node_modules/@patternfly/patternfly/assets/pficon/pficon.woff2 \
    base/acme/webapps/acme/css/assets/pficon
