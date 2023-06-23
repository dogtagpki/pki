#!/bin/sh

VERSION=`jq -r '.dependencies."@patternfly/patternfly"' package.json | sed "s/\^//"`

cp node_modules/@patternfly/patternfly/patternfly.min.css \
    base/server-webapp/webapps/ROOT/patternfly-$VERSION/patternfly.min.css
cp node_modules/@patternfly/patternfly/patternfly.min.css.map \
    base/server-webapp/webapps/ROOT/patternfly-$VERSION/patternfly.min.css.map

cp node_modules/@patternfly/patternfly/assets/fonts/RedHatDisplay/RedHatDisplay-Medium.woff \
    base/server-webapp/webapps/ROOT/patternfly-$VERSION/assets/fonts/RedHatDisplay
cp node_modules/@patternfly/patternfly/assets/fonts/RedHatText/RedHatText-Medium.woff \
    base/server-webapp/webapps/ROOT/patternfly-$VERSION/assets/fonts/RedHatText
cp node_modules/@patternfly/patternfly/assets/fonts/RedHatText/RedHatText-Regular.woff \
    base/server-webapp/webapps/ROOT/patternfly-$VERSION/assets/fonts/RedHatText
cp node_modules/@patternfly/patternfly/assets/fonts/overpass-webfont/overpass-bold.ttf \
    base/server-webapp/webapps/ROOT/patternfly-$VERSION/assets/fonts/overpass-webfont
cp node_modules/@patternfly/patternfly/assets/fonts/overpass-webfont/overpass-bold.woff \
    base/server-webapp/webapps/ROOT/patternfly-$VERSION/assets/fonts/overpass-webfont
cp node_modules/@patternfly/patternfly/assets/fonts/overpass-webfont/overpass-bold.woff2 \
    base/server-webapp/webapps/ROOT/patternfly-$VERSION/assets/fonts/overpass-webfont
cp node_modules/@patternfly/patternfly/assets/fonts/overpass-webfont/overpass-light.ttf \
    base/server-webapp/webapps/ROOT/patternfly-$VERSION/assets/fonts/overpass-webfont
cp node_modules/@patternfly/patternfly/assets/fonts/overpass-webfont/overpass-light.woff \
    base/server-webapp/webapps/ROOT/patternfly-$VERSION/assets/fonts/overpass-webfont
cp node_modules/@patternfly/patternfly/assets/fonts/overpass-webfont/overpass-light.woff2 \
    base/server-webapp/webapps/ROOT/patternfly-$VERSION/assets/fonts/overpass-webfont
cp node_modules/@patternfly/patternfly/assets/fonts/webfonts/fa-solid-900.ttf \
    base/server-webapp/webapps/ROOT/patternfly-$VERSION/assets/fonts/webfonts
cp node_modules/@patternfly/patternfly/assets/fonts/webfonts/fa-solid-900.woff \
    base/server-webapp/webapps/ROOT/patternfly-$VERSION/assets/fonts/webfonts
cp node_modules/@patternfly/patternfly/assets/fonts/webfonts/fa-solid-900.woff2 \
    base/server-webapp/webapps/ROOT/patternfly-$VERSION/assets/fonts/webfonts
cp node_modules/@patternfly/patternfly/assets/images/img_avatar.svg \
    base/server-webapp/webapps/ROOT/patternfly-$VERSION/assets/images
cp node_modules/@patternfly/patternfly/assets/pficon/pficon.ttf \
    base/server-webapp/webapps/ROOT/patternfly-$VERSION/assets/pficon
cp node_modules/@patternfly/patternfly/assets/pficon/pficon.woff \
    base/server-webapp/webapps/ROOT/patternfly-$VERSION/assets/pficon
cp node_modules/@patternfly/patternfly/assets/pficon/pficon.woff2 \
    base/server-webapp/webapps/ROOT/patternfly-$VERSION/assets/pficon
