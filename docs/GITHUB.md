# Publish this tree to GitHub

Replace `YOUR_USER/skillet` with your org and repo name. Update `project.urls` in `pyproject.toml` and the Security Advisory URL in `.github/ISSUE_TEMPLATE/config.yml`.

```bash
git init
git add .
git commit -m "Initial commit: Skillet 0.0.1-beta workspace"
gh repo create skillet --public --source=. --remote=origin --push
```

Tag the beta after the first push:

```bash
git tag v0.0.1-beta
git push origin v0.0.1-beta
```
