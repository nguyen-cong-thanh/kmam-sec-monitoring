#!/bin/sh
# Render config/wazuh_indexer/internal_users.yml from its template, using
# bcrypt hashes of INDEXER_PASSWORD and DASHBOARD_PASSWORD from .env.
# Run once before the first `docker compose up`; the indexer loads this file
# only when it initializes its security index.
set -eu
cd "$(dirname "$0")"
. ./.env

hash() {
    h=$(docker run --rm --entrypoint bash -e JAVA_HOME=/usr/share/wazuh-indexer/jdk \
        wazuh/wazuh-indexer:4.14.10 \
        /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$1" 2>/dev/null | tail -n 1)
    case "$h" in
        '$2y$'*) printf '%s' "$h" ;;
        *) echo "hash.sh failed: $h" >&2; exit 1 ;;
    esac
}

admin=$(hash "$INDEXER_PASSWORD")
kibana=$(hash "$DASHBOARD_PASSWORD")
sed -e "s|__ADMIN_HASH__|$admin|" -e "s|__KIBANASERVER_HASH__|$kibana|" \
    config/wazuh_indexer/internal_users.yml.template > config/wazuh_indexer/internal_users.yml
echo "wrote config/wazuh_indexer/internal_users.yml"
