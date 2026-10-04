#!/bin/bash
# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
#
# Throwaway Odoo servers for the live Odoo connector test (pro/tests/test_odoo_live.py):
# Odoo 18 (XML-RPC) on 127.0.0.1:18069 and Odoo 19 (JSON-2) on 127.0.0.1:19069, one
# Postgres container behind them, nothing published beyond loopback.
#
#   bash pro/tests/odoo_live_stack.sh up <dir>    # writes <dir>/odoo-live.env (mode 600)
#   set -a; . <dir>/odoo-live.env; set +a
#   python pro/tests/test_odoo_live.py
#   bash pro/tests/odoo_live_stack.sh down        # removes the containers, volumes and network
#
# The env file holds generated admin passwords for these containers only.
set -euo pipefail

NET=erebus-odoo-live
PG=erebus-odoo-live-pg
VERSIONS=(18 19)

down() {
  for v in "${VERSIONS[@]}"; do
    docker rm -f "erebus-odoo-live-${v}" >/dev/null 2>&1 || true
    docker volume rm "erebus-odoo-live-${v}" >/dev/null 2>&1 || true
  done
  docker rm -f "$PG" >/dev/null 2>&1 || true
  docker volume rm "${PG}" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}

wait_http() {
  for _ in $(seq 120); do
    curl -sf -o /dev/null "http://127.0.0.1:$1/web/login" && return 0
    sleep 2
  done
  echo "Odoo on port $1 did not come up" >&2
  return 1
}

up() {
  local dir="$1" pg_pw urls="" v port db admin_pw
  mkdir -p "$dir"
  umask 077
  pg_pw="$(openssl rand -hex 16)"
  docker network create "$NET" >/dev/null
  docker run -d --name "$PG" --network "$NET" -e POSTGRES_USER=odoo -e POSTGRES_PASSWORD="$pg_pw" \
    -e POSTGRES_DB=postgres -v "${PG}:/var/lib/postgresql/data" postgres:16-alpine >/dev/null
  for v in "${VERSIONS[@]}"; do
    port="${v}069"
    db="odoo${v}"
    local demo=()
    [ "$v" -lt 19 ] && demo=(--without-demo=all)
    docker run --rm --network "$NET" -e HOST="$PG" -e USER=odoo -e PASSWORD="$pg_pw" \
      -v "erebus-odoo-live-${v}:/var/lib/odoo" "odoo:${v}.0" -- -d "$db" -i contacts,crm "${demo[@]}" \
      --stop-after-init --log-level=warn >/dev/null
    docker run -d --name "erebus-odoo-live-${v}" --network "$NET" -p "127.0.0.1:${port}:8069" \
      -e HOST="$PG" -e USER=odoo -e PASSWORD="$pg_pw" -v "erebus-odoo-live-${v}:/var/lib/odoo" \
      "odoo:${v}.0" -- -d "$db" --db-filter="^${db}\$" --no-database-list >/dev/null
    admin_pw="$(openssl rand -hex 16)"
    docker exec -i -e PGHOST="$PG" -e PGUSER=odoo -e PGPASSWORD="$pg_pw" "erebus-odoo-live-${v}" \
      odoo shell -d "$db" --no-http --log-level=warn >/dev/null <<EOF
env.ref("base.user_admin").password = "${admin_pw}"
env.cr.commit()
EOF
    wait_http "$port"
    urls="${urls:+${urls},}http://admin:${admin_pw}@127.0.0.1:${port}/${db}"
  done
  printf 'EREBUS_TEST_ODOO_URLS=%s\n' "$urls" > "$dir/odoo-live.env"
  chmod 600 "$dir/odoo-live.env"
  echo "wrote $dir/odoo-live.env"
}

case "${1:-}" in
  up) [ -n "${2:-}" ] || { echo "usage: $0 up <dir>" >&2; exit 2; }; down; up "$2" ;;
  down) down ;;
  *) echo "usage: $0 up <dir> | down" >&2; exit 2 ;;
esac
