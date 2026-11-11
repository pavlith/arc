#!/usr/bin/env bash
# Fast M0-M6 checks for the changed code surfaces. No dependency installation.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
python3 scripts/check-agent-setup.py
python3 scripts/check-doc-links.py

mode=changed
base=
if [[ $# -gt 0 ]]; then
  case "$1" in
    --all) mode=all; [[ $# -eq 1 ]] || exit 2 ;;
    --base) [[ $# -eq 2 ]] || exit 2; base=$2 ;;
    *) echo "Usage: $0 [--all | --base GIT_REF]" >&2; exit 2 ;;
  esac
fi

if [[ $mode == all ]]; then
  mapfile -t changed < <(git ls-files | sort -u)
else
  if [[ -z $base ]]; then
    if git rev-parse --verify origin/main >/dev/null 2>&1; then
      base=origin/dev
    elif git rev-parse --verify HEAD^ >/dev/null 2>&1; then
      base=HEAD^
    else
      base=HEAD
    fi
  fi
  git rev-parse --verify "$base^{commit}" >/dev/null
  mapfile -t changed < <(
    {
      git diff --name-only "$base" HEAD
      git diff --name-only HEAD
      git ls-files --others --exclude-standard
    } | sort -u
  )
fi

if [[ ${#changed[@]} -eq 0 ]]; then
  echo "No changed tracked source files; agent setup validated."
  exit 0
fi

# A single Go module does not imply go test ./... for every service change.
declare -A scopes=()
full_go=false
client_ts=false
client_web=false
client_lock=false
migrations_changed=false
for file in "${changed[@]}"; do
  case "$file" in
    client/ts/*) client_ts=true ;;
    client/web/*) client_web=true ;;
    client/package*.json) client_lock=true ;;
  esac
  if [[ $file == migrations/* || $file == */migrations/* ]]; then migrations_changed=true; fi
  case "$file" in
    *.go|go.mod|go.sum)
      if [[ $file == *.go && -f $file ]]; then
        command -v gofmt >/dev/null || { echo "gofmt is required" >&2; exit 1; }
        unformatted=$(gofmt -l "$file")
        [[ -z $unformatted ]] || { echo "Unformatted: $unformatted" >&2; exit 1; }
      fi
      case "$file" in
        go.mod|go.sum|sdk/*|test/*|deploy/migrate/*) full_go=true ;;
        services/*)
          part="${file#services/}"
          owner="${part%%/*}"
          if [[ $part == "$owner" ]]; then scopes["./services"]=1
          else scopes["./services/$owner/..."]=1; fi
          ;;
        cmd/*)
          part="${file#cmd/}"
          owner="${part%%/*}"
          scopes["./cmd/$owner/..."]=1
          ;;
        *) full_go=true ;;
      esac
      ;;
  esac
done
if $full_go; then
  echo "Go: shared changes; testing root module"
  go test ./...
elif [[ ${#scopes[@]} -gt 0 ]]; then
  mapfile -t selected < <(printf '%s\n' "${!scopes[@]}" | sort)
  printf 'Go: targeted tests %s\n' "${selected[*]}"
  go test "${selected[@]}"
else
  echo "Go: no changed Go source"
fi
if $client_ts || $client_web || $client_lock; then
  [[ -d client/node_modules ]] || { echo "Client dependencies missing: npm --prefix client ci" >&2; exit 1; }
  if $client_ts || $client_lock; then npm --prefix client run check --workspace @arc/client; fi
  if $client_web || $client_lock; then
    npm --prefix client run check --workspace ui
    if $client_web; then npm --prefix client run build --workspace ui; fi
  fi
else
  echo "Client: no relevant changes"
fi
if $migrations_changed; then
  echo "NOTICE: migration changes require empty-DB/restart smoke: bash scripts/test-m0-01.sh"
fi
echo "Changed-scope checks complete; M7 full regression not implied."
