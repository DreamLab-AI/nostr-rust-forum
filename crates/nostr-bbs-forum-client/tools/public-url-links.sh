#!/usr/bin/env bash
# Trunk post_build hook: resolve the plain (non-Trunk) asset links in the
# built index.html against the public URL.
#
# The manifest and icon links are ordinary <link> elements, so Trunk leaves
# their relative hrefs alone, and the browser resolves them against the page
# address. On a deep link (/community/<zone>/<section>) that asks for
# /community/<zone>/manifest.webmanifest and gets a 404. Each such link carries
# a `data-public-url` marker; this hook removes the marker and, when the public
# URL is absolute (starts with "/", as with `--public-url /community/`),
# prefixes the relative href with it. A relative public URL ("./") leaves the
# href as it was, which is all such a build can do.
#
# Inputs: TRUNK_STAGING_DIR (the staged dist) and TRUNK_PUBLIC_URL, both set by
# Trunk for hooks. Pure bash, so it runs wherever Trunk does.
set -euo pipefail

html="${TRUNK_STAGING_DIR:?TRUNK_STAGING_DIR is not set}/index.html"
public_url="${TRUNK_PUBLIC_URL:-/}"
doc="$(<"$html")"

marked='<[^>]* data-public-url[^>]*>'
href='href="([^"]*)"'
while [[ $doc =~ $marked ]]; do
    tag="${BASH_REMATCH[0]}"
    new="${tag/ data-public-url/}"
    if [[ $public_url == /* && $new =~ $href ]]; then
        value="${BASH_REMATCH[1]}"
        # Only a relative path: never an absolute path, a URL or a data: URI.
        if [[ -n $value && $value != /* && $value != *:* ]]; then
            new="${new/"href=\"$value\""/"href=\"${public_url%/}/$value\""}"
        fi
    fi
    doc="${doc/"$tag"/"$new"}"
done

printf '%s\n' "$doc" >"$html"
