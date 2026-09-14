# Deployment checklist

- [ ] Validate the `SKILL.md` metadata.
- [ ] Confirm the skill directory name matches `name`.
- [ ] Keep `SKILL.md` under 500 lines.
- [ ] Use only relative paths with forward slashes in `SKILL.md`.
- [ ] Make the task manifest pass `scripts/validate-manifest.py`.
- [ ] Select an execution host strong enough for the task's arbitrary-execution requirement.
- [ ] Deny writable host mounts, host integration, control sockets, and inherited credentials.
- [ ] Specify network grants, resource limits, and the result gate explicitly.
- [ ] Record evidence for every required adversarial test, or mark it `blocked` or `unverified`.
