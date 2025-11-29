package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

// Config represents the proxy configuration
type Config struct {
	Domain        string `json:"domain"`
	CertFile      string `json:"cert_file"`
	KeyFile       string `json:"key_file"`
	ListenAddr    string `json:"listen_addr"`              // e.g. ":443"
	AdminAddr     string `json:"admin_addr"`               // e.g. ":8081"
	UpstreamDNS   string `json:"upstream_dns"`             // e.g. "8.8.8.8:53"
	UpdatePeriod  int    `json:"update_period"`            // in seconds
	ExcludedPorts []int  `json:"excluded_ports,omitempty"` // List of exluded ports
	HostIP        string `json:"host_ip,omitempty"`        // The Host IP Address
	AliasFile     string `json:"alias_file,omitempty"`     // filename to persist aliases
}

// HostEntry represents a DNS/proxy entry
type HostEntry struct {
	Name    string   `json:"name"`
	Url     string   `json:"url"`
	Targets []string `json:"targets"`
	Aliases []string `json:"aliases,omitempty"`
}

var (
	hosts      = map[string]*HostEntry{}
	hostsLock  = sync.RWMutex{}
	cfg        Config
	ddpVersion = "0.1.0"
)

var help = `
DDP(1)                           USER COMMANDS                          DDP(1)

NAME
    ddp - Docker DNS Proxy

SYNOPSIS
    ddp [-c CONFIG] [-v]

DESCRIPTION
    DDP is a simple Docker-aware DNS and HTTPS reverse proxy. It automatically
    discovers Docker containers on the host and exposes them with DNS entries
    and HTTPS URLs under a configured domain.

CONFIGURATION
    Configuration is provided via a JSON file specified with -c. Example:

        {
            "domain": "domain.org",
            "listen_addr": ":443",
            "admin_addr": ":6060",
            "cert_file": "./certs/domain.org.crt",
            "key_file": "./certs/domain.org.key",
            "upstream_dns": "8.8.8.8:53",
            "update_period": 10,
            "excluded_ports": [22, 2375],
            "alias_file": "aliases.json"
        }

ADMIN API
    • List hosts
      GET /hosts
      Response: JSON array of all hosts

    • Add host
      POST /hosts
      Content-Type: application/json
      Body example:
      {
          "name": "service.domain.org",
          "aliases": ["srv.domain.org"]
      }

    • Delete host
      DELETE /hosts/{hostname}
      Example: DELETE /hosts/service.domain.org

    • Add alias to existing host
      POST /hosts/{hostname}/alias
      Content-Type: application/json
      Body example:
      {
          "alias": "srv-main.domain.org"
      }

    • Get DDP version
      GET /version

COMMANDS (DDPCTL)
    ddpctl is the command-line client for managing DDP.

    list
        List all hosts with their targets and aliases.
        Example: ddpctl list --url http://localhost:6060

    add [name] [aliases]
        Add a host with optional comma-separated aliases.
        Example: ddpctl add hasura.z90.org hge.z90.org

    delete [name]
        Delete a host.
        Example: ddpctl delete hasura.z90.org

    alias [host] [alias]
        Add an alias to an existing host.
        Example: ddpctl alias hasura.z90.org hge-main.z90.org

    version
        Show DDP server version.
        Example: ddpctl version --url http://localhost:6060

EXAMPLES
    List all hosts:
        ddpctl list

    Add a host with aliases:
        ddpctl add hasura.z90.org hge.z90.org

    Delete a host:
        ddpctl delete hasura.z90.org

    Add an alias to an existing host:
        ddpctl alias hasura.z90.org hge-main.z90.org

    Show server version:
        ddpctl version

AUTHOR
       Written by pergus.
`

// -------------------------
// Configuration
// -------------------------

func loadConfig(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("failed to read config: %v", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("failed to parse config: %v", err)
	}

	// default alias file
	if cfg.AliasFile == "" {
		cfg.AliasFile = "aliases.json"
	}
}

// -------------------------
// Load Aliases
// -------------------------

func appendIfMissing(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

func loadAliases() {
	data, err := os.ReadFile(cfg.AliasFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("failed to read aliases file: %v", err)
		}
		return
	}

	var aliasMap map[string]string
	if err := json.Unmarshal(data, &aliasMap); err != nil {
		log.Printf("failed to parse aliases file: %v", err)
		return
	}

	hostsLock.Lock()
	defer hostsLock.Unlock()
	for alias, target := range aliasMap {
		h, ok := hosts[target]
		if ok {
			h.Aliases = appendIfMissing(h.Aliases, alias)
			hosts[alias] = h
		}
	}
}

func saveAliasToFile(alias, target string) {
	aliasMap := map[string]string{}

	// read existing aliases
	data, err := os.ReadFile(cfg.AliasFile)
	if err == nil {
		_ = json.Unmarshal(data, &aliasMap)
	}

	// add/update alias
	aliasMap[alias] = target

	// save file
	data, _ = json.MarshalIndent(aliasMap, "", "  ")
	if err := os.WriteFile(cfg.AliasFile, data, 0644); err != nil {
		log.Printf("failed to save alias: %v", err)
	}
}

// -------------------------
// REST Admin API
// -------------------------

func listHosts(w http.ResponseWriter, r *http.Request) {
	hostsLock.RLock()
	defer hostsLock.RUnlock()
	list := []*HostEntry{}
	for _, h := range hosts {
		list = append(list, h)
	}

	// Sort hosts alphabetically by Name
	sort.Slice(list, func(i, j int) bool {
		return list[i].Name < list[j].Name
	})

	_ = json.NewEncoder(w).Encode(list)
}

func addHost(w http.ResponseWriter, r *http.Request) {
	var h HostEntry
	if err := json.NewDecoder(r.Body).Decode(&h); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hostsLock.Lock()
	defer hostsLock.Unlock()
	hosts[h.Name] = &h
	for _, alias := range h.Aliases {
		hosts[alias] = &h
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(h)
}

func deleteHost(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/hosts/")
	hostsLock.Lock()
	defer hostsLock.Unlock()
	h, ok := hosts[name]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	delete(hosts, h.Name)
	for _, a := range h.Aliases {
		delete(hosts, a)
	}
	w.WriteHeader(http.StatusNoContent)
}

func addAlias(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 4 || parts[3] != "alias" {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	hostname := parts[2]
	var payload struct {
		Alias string `json:"alias"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hostsLock.Lock()
	defer hostsLock.Unlock()
	h, ok := hosts[hostname]
	if !ok {
		http.Error(w, "host not found", http.StatusNoContent)
		return
	}
	h.Aliases = appendIfMissing(h.Aliases, payload.Alias)
	hosts[payload.Alias] = h
	// Persist alias to disk
	saveAliasToFile(payload.Alias, hostname)

	_ = json.NewEncoder(w).Encode(h)
}

func adminHelp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(help))
}

func versionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"ddp_version": ddpVersion,
	})
}

func startAdminAPI() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", adminHelp)
	mux.HandleFunc("/version", versionHandler)
	mux.HandleFunc("/hosts", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			listHosts(w, r)
		case "POST":
			addHost(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/hosts/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/alias") && r.Method == "POST" {
			addAlias(w, r)
			return
		}
		if r.Method == "DELETE" {
			deleteHost(w, r)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})

	log.Printf("Admin API running on %s\n", cfg.AdminAddr)
	log.Fatal(http.ListenAndServe(cfg.AdminAddr, mux))
}

// -------------------------
// DNS Server
// -------------------------

func handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true      // we are authoritative for our domain
	msg.RecursionAvailable = true // tell clients recursion is available (we forward unknown queries)

	for _, q := range r.Question {
		log.Printf("[DNS] Query from %s, %d questions", w.RemoteAddr(), len(r.Question))
		log.Printf("[DNS] Question: Name=%s Qtype=%d", q.Name, q.Qtype)

		answered := false

		if strings.HasSuffix(q.Name, cfg.Domain+".") && q.Qtype == dns.TypeA {
			hostsLock.RLock()
			h, ok := hosts[q.Name[:len(q.Name)-1]] // strip trailing dot
			hostsLock.RUnlock()
			if ok {
				log.Printf("[DNS] Found host entry for %s: targets=%v ip=%v", q.Name, h.Targets, cfg.HostIP)

				rr := &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    10,
					},
					A: net.ParseIP(cfg.HostIP), // Respind with the host ip
				}
				msg.Answer = append(msg.Answer, rr)

				_ = w.WriteMsg(msg)
				answered = true
			}
		}

		if !answered {
			log.Printf("[DNS] Forwarding query %s to upstream %s", q.Name, cfg.UpstreamDNS)
			c := new(dns.Client)
			resp, _, err := c.Exchange(r, cfg.UpstreamDNS)
			if err != nil {
				log.Printf("[DNS] DNS forward error: %v", err)
				continue
			}
			_ = w.WriteMsg(resp)
		}
	}
}

func startDNS() {
	dns.HandleFunc(".", handleDNS)
	server := &dns.Server{Addr: ":53", Net: "udp"}
	log.Println("DNS server running on :53")
	log.Fatal(server.ListenAndServe())
}

// -------------------------
// Docker Discovery
// -------------------------

func startDockerWatcher(ctx context.Context) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("failed to create docker client: %v", err)
	}

	// helper to check if port is excluded
	portExcluded := func(port int) bool {
		for _, p := range cfg.ExcludedPorts {
			if p == port {
				return true
			}
		}
		return false
	}

	addContainers := func() {
		containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
		if err != nil {
			log.Printf("docker list error: %v", err)
			return
		}

		hostsLock.Lock()
		defer hostsLock.Unlock()

		for _, c := range containers {
			inspect, err := cli.ContainerInspect(ctx, c.ID)
			if err != nil {
				log.Printf("inspect error: %v", err)
				continue
			}

			ip := ""
			for _, netw := range inspect.NetworkSettings.Networks {
				ip = netw.IPAddress
				break
			}
			if ip == "" {
				continue
			}

			name := strings.TrimPrefix(c.Names[0], "/")

			// iterate over published ports
			for portProto := range inspect.NetworkSettings.Ports {
				containerPort := portProto.Int() // use the container port
				if portExcluded(containerPort) {
					continue
				}
				target := net.JoinHostPort(ip, strconv.Itoa(containerPort))
				h := &HostEntry{
					Name:    name + "." + cfg.Domain,
					Url:     "https://" + name + "." + cfg.Domain,
					Targets: []string{target},
				}
				hosts[h.Name] = h
			}
		}
	}

	// populate existing containers immediately
	addContainers()

	ticker := time.NewTicker(time.Duration(cfg.UpdatePeriod) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			addContainers()
		case <-ctx.Done():
			return
		}
	}
}

// -------------------------
// HTTPS Reverse Proxy
// -------------------------

func reverseProxyHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	hostsLock.RLock()
	h, ok := hosts[host]
	hostsLock.RUnlock()
	if !ok || len(h.Targets) == 0 {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}

	target := h.Targets[0] // pick first target
	u, err := url.Parse("http://" + target)
	if err != nil {
		http.Error(w, "bad target", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		log.Printf("proxy error for %s -> %s: %v", host, target, e)
		http.Error(w, "proxy error", http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, r)
}

func startHTTPSServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", reverseProxyHandler)

	log.Printf("HTTPS reverse proxy running on %s with cert=%s key=%s\n", cfg.ListenAddr, cfg.CertFile, cfg.KeyFile)
	log.Fatal(http.ListenAndServeTLS(cfg.ListenAddr, cfg.CertFile, cfg.KeyFile, mux))
}

// -------------------------
// Help Functions
// -------------------------

func getHostIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// -------------------------
// Main
// -------------------------

func main() {
	configPath := flag.String("config", "config.json", "path to JSON config")
	flag.Parse()

	loadConfig(*configPath)

	// Only call getHostIP if user hasn't set HostIP in config
	if cfg.HostIP == "" {
		ip, err := getHostIP()
		if err != nil {
			log.Printf("Failed to get host IP: %v", err)
		} else {
			cfg.HostIP = ip
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go startDNS()
	go startAdminAPI()
	go startDockerWatcher(ctx)

	// Give Docker watcher a chance to populate hosts before patching aliases
	time.Sleep(500 * time.Millisecond)
	loadAliases()

	startHTTPSServer()
}
