FROM ubuntu:22.04
# Intentional misconfiguration: relies on AuthZ plugin with no request-body-size limits
LABEL scenario="authz-bypass" misconfiguration="no-request-size-limit,authz-plugin-only" cve="CVE-2026-34040"
CMD ["sleep", "infinity"]
