#!/usr/bin/env bash
# Fast M0-M6 checks for the changed code surfaces. No dependency installation.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
python3 scripts/check-agent-setup.py

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
    if git rev-parse --verify origin/dev >/dev/null 2>&1; then
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

declare -A modules=()
client_changed=false
migrations_changed=false
for file in "${changed[@]}"; do
  if [[ $file == client/* ]]; then client_changed=true; fi
  if [[ $file == migrations/* || $file == */migrations/* ]]; then migrations_changed=true; fi
  case "$file" in
    *.go|go.mod|go.sum)
      if [[ $file == *.go && -f $file ]]; then
        command -v gofmt >/dev/null || { echo "gofmt is required" >&2; exit 1; }
        unformatted=$(gofmt -l "$file")
        [[ -z $unformatted ]] || { echo "Unformatted: $unformatted" >&2; exit 1; }
      fi
      dir=$(dirname "$file")
      while [[ $dir != . && $dir != / && ! -f $dir/go.mod ]]; do dir=$(dirname "$dir"); done
      if [[ -f $dir/go.mod ]]; then modules["$dir"]=1; fi
      ;;
  esac
done

if [[ ${#modules[@]} -gt 0 ]]; then
  command -v go >/dev/null || { echo "Go is required for changed Go modules" >&2; exit 1; }
  for module in "${!modules[@]}"; do
    echo "Go check: $module"
    (cd "$module" && go test ./...)
  done
else
  echo "Go: no changed, implemented module"
fi

if $client_changed && [[ -f client/package.json ]]; then
  [[ -d client/node_modules ]] || { echo "Client dependencies missing: npm --prefix client ci" >&2; exit 1; }
  npm --prefix client run check --workspace @arc/web
  npm --prefix client run build --workspace @arc/web
else
  echo "Client: no changed client package"
fi

if $migrations_changed; then
  echo "NOTICE: migration changes require empty-DB/restart smoke: bash scripts/test-m0-01.sh"
fi
echo "Focused checks complete; M7 full regression not implied."
