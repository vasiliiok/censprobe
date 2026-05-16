# Optional: server-side dashboard rendering

Grafana's default install renders dashboards client-side (JavaScript in
the browser). That covers the interactive workflow. Two scenarios need
the sidecar **image renderer** instead:

* **`/render/d/...` REST API** — used by scheduled-snapshot tooling and
  by `Share → Direct link rendered image` in the UI.
* **PDF export** of a whole dashboard.

The renderer ships its own Chromium and adds ~250 MB resident memory,
so it's not enabled by default. Opt in by dropping this file at
`docker-compose.override.yml` (next to `docker-compose.yml`):

```yaml
services:
  grafana:
    environment:
      GF_RENDERING_SERVER_URL: "http://renderer:8081/render"
      GF_RENDERING_CALLBACK_URL: "http://grafana:3000/"
    depends_on:
      renderer:
        condition: service_started

  renderer:
    profiles: [dashboard]
    # Pin both tag and digest so a future minor bump on Docker Hub
    # can't silently change the binary in an existing deployment.
    image: grafana/grafana-image-renderer:5.0.0@sha256:340c91e98ccd65001a3da4d0192fcf0ed13e95609a51a0d62c35a61b6ff28dff
    healthcheck:
      test: ["CMD", "/usr/bin/grafana-image-renderer", "healthcheck"]
      interval: 5s
      timeout: 5s
      retries: 10
      start_period: 10s
    restart: unless-stopped
```

Then `docker compose --profile dashboard up -d` brings the renderer
up alongside the existing dashboard services. Verify with:

```bash
curl -u admin:admin -o test.png \
  "http://127.0.0.1:3000/render/d-solo/censprobe-01?orgId=1&panelId=1&width=800&height=400&var-test_id=<your-test-id>"
file test.png   # PNG image data
```

Pass `var-test_id=<concrete>` rather than relying on the
default `$__all` — Grafana's headless Chromium does not auto-resolve
the all-template-var path and the render hangs on a 408 timeout.
