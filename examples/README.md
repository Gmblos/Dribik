# Examples

Synthetic `.test` names only (RFC 2606). Replace with **in-scope** assets you are authorized to assess.

```bash
skillet init ./workspace --program "Example Corp BB"
skillet scope load ./workspace --file examples/scope.yaml
skillet graph import ./workspace --file examples/assets.json
skillet findings import ./workspace --file examples/findings.json
skillet recon plan ./workspace
skillet report write ./workspace --out ./workspace/report.md
skillet collection write ./workspace --out ./workspace/collection.json
```
