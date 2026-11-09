# afkconvoy config

How the afkconvoy fleet works this repo's backlog: issues in sunfmin/control
labelled `ready-for-agent` and `repo:sunfmin/sesame`, one worker per issue,
landed on `main` behind `./gate.sh`, the same gate a person runs.

```yaml
base_branch: "main"
gate_command: ./gate.sh
gate_seconds: 1200
ready_label: ready-for-agent
```
