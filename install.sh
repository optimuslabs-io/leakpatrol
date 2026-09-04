#!/bin/sh
# Copyright 2026 Optimus Labs (Civilizations research team). Apache-2.0.
#
# leakpatrol installer.
#
#   curl -fsSL https://raw.githubusercontent.com/optimuslabs-io/leakpatrol/main/install.sh | sh
#
# Downloads the release binary for this OS/architecture, verifies it against the
# release's SHA256SUMS, and installs it as `leakpatrol` on your PATH. Reading
# this script before piping it to sh is encouraged -- that is why it lives at a
# stable URL in the repository root.
#
# Environment overrides:
#   LEAKPATROL_VERSION   install a specific tag (e.g. v0.1.0) instead of latest
#
# This script never invokes sudo and never asks you to: it installs into
# ~/.local/bin (created if needed), or /usr/local/bin when that is already
# writable by you. Windows: download leakpatrol_<tag>_windows_amd64.exe
# from the releases page and verify it against SHA256SUMS with
#   Get-FileHash .\leakpatrol_*.exe -Algorithm SHA256
#
# What the checksum buys, honestly stated: SHA256SUMS is published alongside the
# binaries it describes, so it protects against a corrupted download -- not a
# compromised release. For proof a binary was built by this repository's release
# workflow, verify its sigstore provenance:
#   gh attestation verify <binary> -R optimuslabs-io/leakpatrol

set -eu

REPO="optimuslabs-io/leakpatrol"

note() { printf '%s\n' "$*" >&2; }
fail() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

main() {
    command -v curl >/dev/null 2>&1 || fail "curl is required"

    case "$(uname -s)" in
        Darwin) os=darwin ;;
        Linux)  os=linux ;;
        *) fail "unsupported OS '$(uname -s)' -- on Windows, download the .exe from https://github.com/$REPO/releases" ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64)  arch=amd64 ;;
        arm64|aarch64) arch=arm64 ;;
        *) fail "unsupported architecture '$(uname -m)'" ;;
    esac

    if [ -n "${LEAKPATROL_VERSION:-}" ]; then
        tag="$LEAKPATROL_VERSION"
    else
        tag="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")"
        tag="${tag##*/}"
        case "$tag" in
            v[0-9]*) ;;
            latest) fail "no releases published yet at https://github.com/$REPO/releases" ;;
            *) fail "could not determine the latest release tag (got '$tag')" ;;
        esac
    fi

    asset="leakpatrol_${tag}_${os}_${arch}"
    base="https://github.com/$REPO/releases/download/$tag"

    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT INT TERM

    note "downloading $asset ($tag) ..."
    curl -fsSL -o "$tmp/$asset" "$base/$asset" || fail "download failed: $base/$asset"
    curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" || fail "download failed: $base/SHA256SUMS"

    note "verifying checksum ..."
    if command -v sha256sum >/dev/null 2>&1; then
        sumtool="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        sumtool="shasum -a 256"
    else
        fail "neither sha256sum nor shasum found; refusing to install unverified"
    fi
    grep " $asset\$" "$tmp/SHA256SUMS" > "$tmp/expected.sum" || fail "$asset is not listed in SHA256SUMS"
    ( cd "$tmp" && $sumtool -c expected.sum >/dev/null ) || fail "checksum mismatch for $asset -- refusing to install"

    # Install into the user's own bin dir, creating it if needed -- never sudo.
    # /usr/local/bin is used only when it is already writable by this user.
    dir="$HOME/.local/bin"
    if [ -w /usr/local/bin ]; then
        case ":$PATH:" in
            *":$HOME/.local/bin:"*) ;;
            *) dir="/usr/local/bin" ;;
        esac
    fi
    mkdir -p "$dir" || fail "cannot create $dir"

    install -m 0755 "$tmp/$asset" "$dir/leakpatrol"
    note "installed $dir/leakpatrol"
    case ":$PATH:" in
        *":$dir:"*) ;;
        *) note "note: $dir is not on your PATH; add it, or run $dir/leakpatrol directly" ;;
    esac
    "$dir/leakpatrol" --version >&2
}

# Nothing executes until the whole script has arrived.
main "$@"
