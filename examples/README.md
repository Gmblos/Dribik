# Examples

Synthetic `.test` names only (RFC 2606). Replace with **in-scope** assets you are authorized to assess.

```bash
dribik init ./workspace --program "Example Corp BB"
dribik scope load ./workspace --file examples/scope.yaml
dribik graph import ./workspace --file examples/assets.json
dribik findings import ./workspace --file examples/findings.json
dribik recon plan ./workspace
dribik report write ./workspace --out ./workspace/report.md
dribik collection write ./workspace --out ./workspace/collection.json
```
