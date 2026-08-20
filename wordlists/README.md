# wordlists/

Files mounted into the container at `/opt/wordlists` (see `docker-compose.yml`).

- **`resolvers.txt`** — a small set of reliable public DNS resolvers for
  `puredns` (Stage 2). Point `config.yaml` at it to use it:

  ```yaml
  validation:
    puredns:
      resolvers: "/opt/wordlists/resolvers.txt"   # in-container path
  ```

  For large scans, replace this with a freshly validated resolver list
  (e.g. generated with [dnsvalidator](https://github.com/vortexau/dnsvalidator))
  — stale or rate-limited resolvers cause false negatives.

Add any other wordlists here (e.g. cloud-enum mutations, dnsgen wordlists) and
reference them by their `/opt/wordlists/...` path in `config.yaml`.
