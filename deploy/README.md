# Deploying pqproxy

## Files

| Path | Purpose |
|------|---------|
| `pqproxy.service` | systemd unit |
| `../config/pqproxy.example.yaml` | production-oriented YAML |
| `../config/pqproxy.dev.yaml` | plain-TCP local development |
| `grafana/pqproxy-dashboard.json` | Grafana dashboard (Prometheus) |
| `grafana/prometheus-scrape.snippet.yml` | Prometheus scrape job |

## Install (sketch)

```bash
# Build
cmake -B build -S . -DPIQUE_ROOT=$HOME/pique -DLIBYAML_ROOT=$HOME/libyaml
cmake --build build
sudo install -m 755 build/pqproxy /usr/local/bin/pqproxy

# Config + certs
sudo useradd --system --no-create-home --shell /usr/sbin/nologin pqproxy
sudo mkdir -p /etc/pqproxy/certs
sudo cp config/pqproxy.example.yaml /etc/pqproxy/pqproxy.yaml
# Install server.crt, server.key, ca.crt; chown root:pqproxy; chmod 640 keys
sudo install -m 644 deploy/pqproxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pqproxy
```

## Metrics

Default scrape endpoint: `http://127.0.0.1:9108/metrics`

Import `grafana/pqproxy-dashboard.json` (Dashboard → Import) and point the
Prometheus data source at a Prometheus that scrapes that endpoint.
