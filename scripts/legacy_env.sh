#!/usr/bin/env bash

# Promote pre-Judikt variables without overriding explicitly configured values.
for legacy_prefix in MCP_GUARD_; do
  while IFS="=" read -r name value; do
    if [[ "${name}" != "${legacy_prefix}"* ]]; then
      continue
    fi
    suffix="${name#"${legacy_prefix}"}"
    judikt_name="JUDIKT_${suffix}"
    if [[ -z "${!judikt_name+x}" ]]; then
      export "${judikt_name}=${value}"
    fi
  done < <(env)
done
