#!/usr/bin/env bash
set -euo pipefail

agent_binary=/usr/local/bin/arc-agent
agent_config=/etc/arc-agent/config.json
agent_unit=/etc/systemd/system/arc-agent.service
docker_socket=/var/run/docker.sock
unit_source="$(dirname -- "${BASH_SOURCE[0]}")/arc-agent.service"

usage() {
  printf '%s\n' 'Usage: bash deploy/agent/install.sh list | plan | apply /path/to/arc-agent [--with-docker]'
}

fail() {
  printf 'arc-agent setup: %s\n' "$1" >&2
  exit 1
}

docker_ready() {
  command -v docker >/dev/null &&
    env -u DOCKER_HOST -u DOCKER_CONTEXT timeout 10s docker \
      --host "unix://$docker_socket" version --format '{{.Server.Version}}' >/dev/null 2>&1
}

setup_docker() {
  if docker_ready; then
    return
  fi
  local load_state
  load_state=$(systemctl show --property=LoadState --value docker.service)
  case "$load_state" in
    loaded)
      systemctl start docker.service
      ;;
    not-found)
      if command -v docker >/dev/null || [[ -e $docker_socket ]]; then
        fail 'existing Docker installation is unavailable on the local socket'
      fi
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-remove docker.io
      systemctl enable --now docker.service
      ;;
    *) fail 'Docker systemd unit is unavailable' ;;
  esac
  docker_ready || fail 'Docker Engine did not respond on the local socket'
}

replace_file() {
  local source=$1 destination=$2 mode=$3 temporary
  temporary=$(mktemp -- "${destination}.XXXXXX")
  if ! install -m "$mode" -- "$source" "$temporary" || ! mv -fT -- "$temporary" "$destination"; then
    rm -f -- "$temporary"
    fail 'could not install Agent files'
  fi
}

setup_agent() {
  local source=$1 changed=false
  if [[ -L $agent_binary ]] || ! cmp -s -- "$source" "$agent_binary" || [[ ! -x $agent_binary ]]; then
    replace_file "$source" "$agent_binary" 0755
    changed=true
  fi
  if [[ -L $agent_unit ]] || ! cmp -s -- "$unit_source" "$agent_unit"; then
    replace_file "$unit_source" "$agent_unit" 0644
    changed=true
  fi
  if "$changed" || [[ $(systemctl show --property=NeedDaemonReload --value arc-agent.service) == yes ]]; then
    systemctl daemon-reload
  fi
  if ! systemctl is-enabled --quiet arc-agent.service; then
    systemctl enable arc-agent.service
  fi
  if systemctl is-active --quiet arc-agent.service; then
    if "$changed"; then
      systemctl restart arc-agent.service
    fi
  else
    systemctl start arc-agent.service
  fi
}

apply() {
  local source=$1
  [[ $EUID == 0 ]] || fail 'apply requires root'
  [[ -r /etc/os-release ]] || fail 'cannot identify host operating system'
  ( . /etc/os-release; [[ ${ID:-} == ubuntu ]] ) || fail 'apply requires Ubuntu'
  [[ -d /run/systemd/system ]] || fail 'apply requires systemd'
  [[ -f $source && -x $source ]] || fail 'supply an executable Arc Agent binary'
  [[ -f $unit_source ]] || fail 'the bundled Agent unit is missing'
  "$(realpath -- "$source")" -config "$agent_config" -check-config

  if [[ ${2:-} == --with-docker ]]; then
    setup_docker
  fi
  setup_agent "$source"
  systemctl is-active --quiet arc-agent.service || fail 'Arc Agent is inactive'
  if [[ ${2:-} == --with-docker ]]; then
    docker_ready || fail 'Docker Engine is unavailable'
  fi
  printf '%s\n' 'arc-agent.service is active. Docker is optional and managed separately.'
}

case "${1:-}" in
  list)
    [[ $# == 1 ]] || { usage >&2; exit 2; }
    printf '%s\n' preflight agent.install verify docker.optional
    ;;
  plan)
    [[ $# == 1 ]] || { usage >&2; exit 2; }
    printf '%s\n' \
      'preflight     Validate Ubuntu, systemd, the Agent binary and its config.' \
      'docker.optional Optionally install Ubuntu docker.io with --with-docker.' \
      'agent.install Install and enable the Agent systemd unit and binary.' \
      'verify        Check the local Docker API and Agent systemd status.'
    ;;
  apply)
    [[ $# == 2 || ( $# == 3 && $3 == --with-docker ) ]] || { usage >&2; exit 2; }
    apply "$2" "${3:-}"
    ;;
  -h|--help) usage ;;
  *) usage >&2; exit 2 ;;
esac
