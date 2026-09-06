# Dribik local practice lab

This tiny server is intentionally insecure so you can verify Dribik against a target you control.
It uses only the Python standard library and binds to `127.0.0.5:8080` by default. `127.0.0.5` is
inside the IPv4 loopback range, so the server cannot be reached from another machine.

## 1. Start the practice server

From the repository root, open a terminal and run:

```bash
python examples/local_lab/server.py
```

Leave that terminal open. Stop the server later with `Ctrl+C`.

## 2. Create a Dribik practice workspace

Open another terminal in the repository root:

```bash
dribik init ./local-lab-workspace --program "My local Dribik practice lab"
dribik scope load ./local-lab-workspace --file examples/local_lab/scope.yaml
dribik consent grant ./local-lab-workspace --target 127.0.0.5 \
  --capability active_exploitation --operator "local-user" \
  --note "I own and operate the local 127.0.0.5 practice server"
```

## 3. Run safe, local checks

```bash
# Finds deliberately missing security headers and the practice CORS configuration.
dribik scan headers ./local-lab-workspace --url http://127.0.0.5:8080/ --save

# Discovers /robots.txt, /sitemap.xml, /docs, /api/status, and /admin.
dribik scan content ./local-lab-workspace --url http://127.0.0.5:8080/ --import-graph

# Crawls only the loopback practice server.
dribik scan crawl ./local-lab-workspace --url http://127.0.0.5:8080/ --import-graph

# Detects the deliberately reflected `q` value at the local /search endpoint.
dribik scan xss ./local-lab-workspace --url "http://127.0.0.5:8080/search?q=hello" --save

# Checks the deliberately unsafe local redirect handler.
dribik scan redirect ./local-lab-workspace --url "http://127.0.0.5:8080/redirect?next=/" --save

dribik report html ./local-lab-workspace --out ./local-lab-report.html
```

Open `local-lab-report.html` in a browser to review the locally generated report. The server and
workspace contain no third-party targets or credentials.
