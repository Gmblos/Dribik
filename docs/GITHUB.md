# GitHub maintenance

The canonical repository is [Gmblos/Dribik](https://github.com/Gmblos/Dribik). It is configured
with a pull-request template, structured bug and feature forms, CI, and a private security-reporting
link.

## Maintainer release checklist

1. Run `ruff check src tests`, `mypy src`, and `pytest -q --cov=dribik --cov-fail-under=70`.
2. Update `CHANGELOG.md` and the version in `pyproject.toml` and `src/dribik/__init__.py`.
3. Commit the release, tag it (for example, `v0.1.0-beta`), and push the tag.
4. Create a GitHub Release from the tag and paste the matching changelog section into its notes.

## Repository settings worth enabling

- Require the CI workflow to pass before merging into `main`.
- Enable private vulnerability reporting and GitHub Dependabot alerts.
- Protect `main` from force pushes and require pull requests for changes.
