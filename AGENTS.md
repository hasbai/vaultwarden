# Agent instructions

Applies to this repository.

- The primary agent must spawn `architect` before proceeding with a large plan, when the same error repeats, and before declaring a long task complete. Wait for its review and address its findings.
- Read [the branch and production deployment policy](cloudflare/README.md#branch-and-production-policy) before branch, merge or deployment work.
- For Worker development, read [cloudflare/README.md](cloudflare/README.md) for identity boundaries, supported features, setup and task-specific validation. Native server and Docker changes use the existing upstream documentation linked from [README.md](README.md).
