# Docker DNS Proxy (DDP)

[![Go](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Docker DNS Proxy (DDP) is a Docker-aware DNS and HTTPS reverse proxy that automatically discovers running Docker containers and exposes them via DNS entries and HTTPS URLs under a configured domain. It also provides an Admin API for programmatic host and target management. The `ddpctl` CLI provides convenient access to the Admin API.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [ddp (Server)](#ddp-server)
  - [ddpctl (CLI)](#ddpctl-cli)
- [Access Docker Containers](#access-docker-containers)
- [Admin API](#admin-api)
- [License](#license)

---

## Features

- Auto-discover Docker containers and expose them with friendly DNS and HTTPS URLs.
- Each host can have multiple targets, but only one can be selected as the active target.
- Add/remove hosts and aliases dynamically.
- JSON-based Admin API with optional pretty printing.
- CLI tool (`ddpctl`) for quick administration of hosts, aliases, and targets.

---

## Installation

### Build from Source

```bash
git clone https://github.com/pergus/docker-dns-proxy.git
cd docker-dns-proxy
cd ddp
go build
cd ../ddpctl
go build
```


---

## Usage

### ddp (Server)

Run the server:

```bash
./ddp -c config.json
```

Where `config.json` is a JSON configuration file with your domain, listen addresses, TLS certificates, and optional token.

The server exposes:

- DNS on `dns_addr` (default `:53`)
- HTTPS reverse proxy on `listen_addr` (default `:443`)
- Admin API on `admin_addr` (default `:6060`)

#### configuration

`config.json` example:

```json
{
  "domain": "example.org",
  "listen_addr": ":443",
  "admin_addr": ":6060",
  "cert_file": "/certs/example.org.crt",
  "key_file": "/certs/example.org.key",
  "upstream_dns": "8.8.8.8:53",
  "dns_addr": ":53",
  "update_period": 10,
  "excluded_ports": [22, 2375],
  "host_ip": "192.168.1.100",
  "alias_file": "aliases.json",
  "token": "ThisIsASecretToken"
}
```

---

### ddpctl (CLI)

The `ddpctl` CLI communicates with the Admin API to manage hosts and targets.

```bash
./ddpctl --url https://<server>:6060 --token <your-token> <command> [args]
```

#### Commands

- `list` – List all hosts
- `add [name] [aliases]` – Add a host with optional aliases
- `delete [name]` – Remove a host
- `alias [host] [alias]` – Add an alias to a host
- `list-targets` – List all targets for all hosts
- `targets [host]` – List all targets for a specific host
- `set-target [host] [index]` – Set active target index for a host
- `version` – Show ddp server version
- `manual` – Show the full help text

Example:

```bash
./ddpctl --url https://localhost:6060 --token "secret-token" list
```

---

## Access Docker Containers

DDP automatically discovers running Docker containers and exposes them under the configured domain.

#### Example

Suppose you have a Docker container named `webapp` running on port 8080.

- DDP creates a DNS entry: `webapp.mydomain`
- Access it via HTTPS: `https://webapp.mydomain`

Aliases and multiple targets per host can be managed using `ddpctl` or the Admin API.

---

## Admin API

All endpoints respond with JSON. Append `?pretty` to pretty-print JSON.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/hosts` | List all hosts |
| POST   | `/hosts` | Add a host |
| DELETE | `/hosts/{hostname}` | Delete a host |
| POST   | `/hosts/{hostname}/alias` | Add an alias |
| GET    | `/hosts/{hostname}/targets` | List targets for a host |
| POST   | `/hosts/{hostname}/target` | Set active target |
| GET    | `/version` | Get DDP server version |

**Example with Bearer token:**

```bash
curl -H "Authorization: Bearer <token>" https://<server>:6060/hosts?pretty
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

**Author:** pergus