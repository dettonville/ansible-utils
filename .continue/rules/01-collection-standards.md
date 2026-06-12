---
name: Ansible Collection Standards
globs: ["**/*.{py,yml,yaml}"]
alwaysApply: true
description: Core standards for dettonville.utils collection
---

# Collection Development Standards

- Follow official Ansible Collection guidelines
- All modules/filters must have complete DOCUMENTATION, EXAMPLES, and RETURN sections
- Maintain high test coverage (unit + integration)
- Use ansible-test sanity, unit, and integration tests
- Prefer idempotency and clear error messages
- Keep code modular and reusable
