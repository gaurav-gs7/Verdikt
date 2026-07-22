#!/usr/bin/env bash

# Promote pre-Verdikt variables without overriding explicitly configured values.
while IFS='=' read -r name value; do
  if [[ "${name}" == MCP_GUARD_* ]]; then
    verdikt_name="VERDIKT_${name#MCP_GUARD_}"
    if [[ -z "${!verdikt_name+x}" ]]; then
      export "${verdikt_name}=${value}"
    fi
  fi
done < <(env)
