#!/usr/bin/env bash
#
# cut-release.sh - cut a fork release for Neo Backup.
#
# Automates the manual release steps so a new fork version is one command:
#   1. Bump versionName + versionCode in build.gradle.kts.
#      MAJOR/MINOR are left untouched on purpose - they are the backup on-disk
#      format version (backupVersionCode = MAJOR*1000+MINOR, restore gates on
#      backupVersionCode >= 8000), not the app's marketing version.
#   2. Promote the "Unreleased" section of CHANGELOG.md to a dated version header.
#   3. Generate the Fastlane en-US changelog keyed by the new versionCode.
#   4. Commit, tag v<versionName>, and (optionally) push to trigger the
#      .github/workflows/release.yml build + GitHub Release.
#
# Usage:
#   scripts/cut-release.sh [options] [VERSION]
#
#   VERSION            Explicit versionName (e.g. 8.4.0-fork.1). If omitted, the
#                      current "-fork.N" suffix is incremented, or "-fork.1" is
#                      appended when there is no fork suffix yet.
#
# Options:
#   --code N           Explicit versionCode (default: current + 1).
#   --date D           Changelog date, dd.mm.yyyy (default: today).
#   --fastlane FILE    Use FILE as the Fastlane changelog body instead of
#                      generating it from CHANGELOG.md.
#   --push             Push the current branch and the new tag (triggers CI).
#   --no-commit        Edit files only; do not commit or tag.
#   --no-tag           Commit the release, but do not create a tag.
#   --allow-dirty      Skip the clean-working-tree check.
#   --force            Overwrite an existing Fastlane changelog for the new code.
#   -n, --dry-run      Show what would happen without changing anything.
#   -h, --help         Show this help and exit.
#
set -euo pipefail

# ---- helpers ----------------------------------------------------------------
err()  { printf 'error: %s\n' "$*" >&2; exit 1; }
warn() { printf 'warning: %s\n' "$*" >&2; }
info() { printf '%s\n' "$*"; }
run()  { # echo + execute, unless dry-run
  printf '  + %s\n' "$*"
  $DRY_RUN || eval "$@"
}

usage() { sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; s/^#$//' | sed '$d'; }

# ---- defaults / arg parsing -------------------------------------------------
VERSION=""
NEW_CODE=""
DATE=""
FASTLANE_FILE=""
PUSH=false
DO_COMMIT=true
DO_TAG=true
ALLOW_DIRTY=false
FORCE=false
DRY_RUN=false

while [ $# -gt 0 ]; do
  case "$1" in
    --code)        NEW_CODE="${2:-}"; shift 2 ;;
    --date)        DATE="${2:-}"; shift 2 ;;
    --fastlane)    FASTLANE_FILE="${2:-}"; shift 2 ;;
    --push)        PUSH=true; shift ;;
    --no-commit)   DO_COMMIT=false; DO_TAG=false; shift ;;
    --no-tag)      DO_TAG=false; shift ;;
    --allow-dirty) ALLOW_DIRTY=true; shift ;;
    --force)       FORCE=true; shift ;;
    -n|--dry-run)  DRY_RUN=true; shift ;;
    -h|--help)     usage; exit 0 ;;
    --)            shift; break ;;
    -*)            err "unknown option: $1 (see --help)" ;;
    *)             [ -z "$VERSION" ] || err "unexpected argument: $1"; VERSION="$1"; shift ;;
  esac
done

# ---- locate repo ------------------------------------------------------------
ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || err "not inside a git repository"
cd "$ROOT"
GRADLE="build.gradle.kts"
CHANGELOG="CHANGELOG.md"
FASTLANE_DIR="fastlane/metadata/android/en-US/changelogs"
[ -f "$GRADLE" ]    || err "$GRADLE not found"
[ -f "$CHANGELOG" ] || err "$CHANGELOG not found"

# ---- read current version ---------------------------------------------------
CUR_CODE="$(awk 'match($0,/versionCode[[:space:]]*=[[:space:]]*[0-9]+/){s=substr($0,RSTART,RLENGTH); gsub(/[^0-9]/,"",s); print s; exit}' "$GRADLE")"
CUR_NAME="$(awk 'match($0,/versionName[[:space:]]*=[[:space:]]*"[^"]*"/){l=substr($0,RSTART,RLENGTH); if(match(l,/"[^"]*"/)){print substr(l,RSTART+1,RLENGTH-2)}; exit}' "$GRADLE")"
[ -n "$CUR_CODE" ] || err "could not read versionCode from $GRADLE"
[ -n "$CUR_NAME" ] || err "could not read versionName from $GRADLE"

# ---- compute new version ----------------------------------------------------
if [ -z "$VERSION" ]; then
  if [[ "$CUR_NAME" =~ ^(.*)-fork\.([0-9]+)$ ]]; then
    VERSION="${BASH_REMATCH[1]}-fork.$(( BASH_REMATCH[2] + 1 ))"
  else
    VERSION="${CUR_NAME}-fork.1"
  fi
fi
[ -z "$NEW_CODE" ] && NEW_CODE=$(( CUR_CODE + 1 ))
[ -z "$DATE" ] && DATE="$(date +%d.%m.%Y)"

case "$NEW_CODE" in *[!0-9]*|'') err "versionCode must be an integer: $NEW_CODE" ;; esac
[ "$NEW_CODE" -gt "$CUR_CODE" ] || err "new versionCode ($NEW_CODE) must be greater than current ($CUR_CODE)"
[ "$VERSION" != "$CUR_NAME" ] || err "new versionName equals current ($CUR_NAME); pass an explicit VERSION"

TAG="v$VERSION"
FASTLANE_OUT="$FASTLANE_DIR/$NEW_CODE.txt"

# ---- preflight checks -------------------------------------------------------
CUR_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
DEFAULT_BRANCH="$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null | sed 's#origin/##')"
[ -n "$DEFAULT_BRANCH" ] || DEFAULT_BRANCH="main"
if [ "$CUR_BRANCH" != "$DEFAULT_BRANCH" ]; then
  warn "on branch '$CUR_BRANCH' (default is '$DEFAULT_BRANCH'); the tag will point at this branch's commit"
fi
if $DO_TAG && git rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1; then
  err "tag $TAG already exists"
fi
if $DO_COMMIT && ! $ALLOW_DIRTY; then
  git diff --quiet && git diff --cached --quiet || \
    err "working tree is not clean; commit/stash first or pass --allow-dirty"
fi

info "Cutting release:"
info "  versionName : $CUR_NAME  ->  $VERSION"
info "  versionCode : $CUR_CODE  ->  $NEW_CODE"
info "  date        : $DATE"
info "  tag         : $([ "$DO_TAG" = true ] && echo "$TAG" || echo '(skipped)')"
info "  fastlane    : $FASTLANE_OUT"
$DRY_RUN && info "(dry run - no changes will be written)"
info ""

# ---- 1. bump build.gradle.kts ----------------------------------------------
info "Updating $GRADLE"
if ! $DRY_RUN; then
  tmp="$(mktemp)"
  CUR_CODE="$CUR_CODE" NEW_CODE="$NEW_CODE" CUR_NAME="$CUR_NAME" NEW_NAME="$VERSION" \
  awk '
    !dc && $0 ~ ("versionCode[[:space:]]*=[[:space:]]*" ENVIRON["CUR_CODE"]) {
      sub("versionCode[[:space:]]*=[[:space:]]*" ENVIRON["CUR_CODE"], "versionCode = " ENVIRON["NEW_CODE"]); dc=1
    }
    !dn && index($0, "versionName = \"" ENVIRON["CUR_NAME"] "\"") {
      sub(/versionName[[:space:]]*=[[:space:]]*"[^"]*"/, "versionName = \"" ENVIRON["NEW_NAME"] "\""); dn=1
    }
    { print }
    END { if(!dc) exit 3; if(!dn) exit 4 }
  ' "$GRADLE" > "$tmp" || { rc=$?; rm -f "$tmp"; [ "$rc" = 3 ] && err "could not find versionCode line to update"; [ "$rc" = 4 ] && err "could not find versionName line to update"; err "failed updating $GRADLE"; }
  mv "$tmp" "$GRADLE"
fi

# ---- 2. promote CHANGELOG Unreleased ---------------------------------------
info "Promoting Unreleased -> $VERSION in $CHANGELOG"
if ! $DRY_RUN; then
  tmp="$(mktemp)"
  awk -v header="$VERSION ($DATE)" '
    BEGIN { st = 0 }
    st==0 && $0=="Unreleased" { print; st=1; next }
    st==1 && /^-+$/            { print; st=2; next }
    st==2 {
      if ($0 == "") { print; print header; print "------------"; print ""; st=3; next }
      else          { print header; print "------------"; print ""; print; st=3; next }
    }
    { print }
    END { if (st < 3) exit 5 }
  ' "$CHANGELOG" > "$tmp" || { rm -f "$tmp"; err "no 'Unreleased' section found in $CHANGELOG"; }
  mv "$tmp" "$CHANGELOG"
fi

# ---- 3. Fastlane en-US changelog -------------------------------------------
if [ -f "$FASTLANE_OUT" ] && ! $FORCE && [ -z "$FASTLANE_FILE" ]; then
  warn "$FASTLANE_OUT already exists; leaving it as is (use --force to regenerate)"
elif ! $DRY_RUN; then
  info "Writing $FASTLANE_OUT"
  mkdir -p "$FASTLANE_DIR"
  if [ -n "$FASTLANE_FILE" ]; then
    [ -f "$FASTLANE_FILE" ] || err "--fastlane file not found: $FASTLANE_FILE"
    cp "$FASTLANE_FILE" "$FASTLANE_OUT"
  else
    notes="$(awk -v v="$VERSION" '
      /^[0-9]/ && index($0,v)==1 { s=1; next }
      s && /^[0-9]+\.[0-9]+\.[0-9]+/ { exit }
      s { print }
    ' "$CHANGELOG" | sed -E '/^-+$/d; /^###[[:space:]]*/d' | awk '
      { a[NR]=$0; if ($0 ~ /[^[:space:]]/) { if (!first) first=NR; last=NR } }
      END { if (first) for (i=first;i<=last;i++) print a[i] }
    ')"
    if [ -z "$notes" ]; then
      warn "Unreleased section was empty; writing a placeholder Fastlane changelog"
      notes="Maintenance and translation updates."
    fi
    printf '%s\n' "$notes" > "$FASTLANE_OUT"
  fi
  len=$(wc -c < "$FASTLANE_OUT" | tr -d ' ')
  [ "$len" -le 500 ] || warn "$FASTLANE_OUT is $len chars (>500); Google Play truncates release notes"
else
  info "Would write $FASTLANE_OUT"
fi

# ---- 4. commit / tag / push -------------------------------------------------
info ""
if $DO_COMMIT; then
  run "git add $GRADLE $CHANGELOG $FASTLANE_OUT"
  run "git commit -m 'Release $VERSION'"
  if $DO_TAG; then
    run "git tag -a $TAG -m 'Release $VERSION'"
  fi
  if $PUSH; then
    run "git push origin $CUR_BRANCH"
    $DO_TAG && run "git push origin $TAG"
  fi
else
  info "Files updated (no commit). Review with: git diff"
fi

# ---- next steps -------------------------------------------------------------
info ""
info "Done."
if ! $DO_COMMIT; then
  :
elif ! $DO_TAG; then
  info "Committed. Create and push a tag when ready to release."
elif $PUSH; then
  info "Pushed $TAG - the release workflow will build the APK and publish the GitHub Release."
else
  info "Next: push to publish the release:"
  info "  git push origin $CUR_BRANCH && git push origin $TAG"
fi
