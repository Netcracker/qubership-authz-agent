#!/usr/bin/env bash

# Copyright 2024-2026 Netcracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Shared PostgreSQL init script for the parity stack (D-I + D-J).
# The official postgres image runs scripts in /docker-entrypoint-initdb.d/ on
# first start of an empty data directory. We create two distinct logical
# databases and users - one for legacy access-control and one for identity-provider.
# The init block uses $POSTGRES_USER (the superuser declared on the postgres
# service in docker-compose.yml) to create both roles.
set -euo pipefail

AC_DB="${PARITY_AC_DB:-access_control}"
AC_USER="${PARITY_AC_USER:-access_control}"
AC_PASSWORD="${PARITY_AC_PASSWORD:-access_control}"

IDP_DB="${PARITY_IDP_DB:-identity_provider}"
IDP_USER="${PARITY_IDP_USER:-identity_provider}"
IDP_PASSWORD="${PARITY_IDP_PASSWORD:-identity_provider}"

psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname "postgres" <<EOSQL
CREATE ROLE ${AC_USER} LOGIN PASSWORD '${AC_PASSWORD}';
CREATE DATABASE ${AC_DB} OWNER ${AC_USER};
GRANT ALL PRIVILEGES ON DATABASE ${AC_DB} TO ${AC_USER};

CREATE ROLE ${IDP_USER} LOGIN PASSWORD '${IDP_PASSWORD}';
CREATE DATABASE ${IDP_DB} OWNER ${IDP_USER};
GRANT ALL PRIVILEGES ON DATABASE ${IDP_DB} TO ${IDP_USER};
EOSQL
