package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

// Config represents the proxy configuration
type Config struct {
	Domain        string `json:"domain"`
	CertFile      string `json:"cert_file"`
	KeyFile       string `json:"key_file"`
	ProxyAddr     string `json:"proxy_address"`            // e.g. ":443"
	AdminAddr     string `json:"admin_address"`            // e.g. ":8081"
	DNSAddr       string `json:"dns_address"`              // e.g. ":53"
	UpstreamDNS   string `json:"upstream_dns_address"`     // e.g. "8.8.8.8:53"
	UpdatePeriod  int    `json:"update_period"`            // in seconds
	ExcludedPorts []int  `json:"excluded_ports,omitempty"` // List of exluded ports
	HostIP        string `json:"host_ip,omitempty"`        // The Host IP Address
	AliasFile     string `json:"alias_file,omitempty"`     // filename to persist aliases
	Token         string `json:"token"`                    // Bearer token
}

// HostEntry represents a DNS/proxy entryf
type HostEntry struct {
	Name         string   `json:"name"`
	Url          string   `json:"url"`
	Targets      []string `json:"targets"`
	ActiveTarget int      `json:"active_target"`
	Aliases      []string `json:"aliases,omitempty"`
}

var (
	hosts      = map[string]*HostEntry{}
	hostsLock  = sync.RWMutex{}
	cfg        Config
	ddpVersion = "0.1.2"
)

var manual = `
DDP(1)                           USER COMMANDS                          DDP(1)

NAME
    ddp - Docker DNS Proxy

SYNOPSIS
    ddp [-c CONFIG] [-v]

DESCRIPTION
    DDP is a Docker-aware DNS and HTTPS reverse proxy. It automatically
    discovers Docker containers on the host and exposes them with DNS entries
    and HTTPS URLs under a configured domain.

CONFIGURATION
    Configuration is provided via a JSON file specified with -c.

CONFIGURATION OPTIONS
    The following options are available in the JSON config file:

    Required:
        "domain"                - The domain under which hosts will be exposed, e.g., "domain.org".
        "proxy_address"         - Address for the HTTPS reverse proxy to listen on, e.g., ":443".
        "admin_address"         - Address for the admin HTTP API, e.g., ":6060".
        "cert_file"             - Path to the TLS certificate file for HTTPS.
        "key_file"              - Path to the TLS key file for HTTPS.
        "upstream_dns_address"  - Upstream DNS server to forward unknown queries to, e.g., "8.8.8.8:53".

    Optional:
        "dns_address"           - Address for the DNS server to listen on (default ":53").
        "update_period"         - Period (in seconds) to refresh Docker container information (default 10).
        "excluded_ports"        - List of container ports to ignore, e.g., [22, 2375].
        "host_ip"               - IP returned in DNS responses (default: auto-detected).
        "alias_file"            - Path to file where aliases are persisted (default "aliases.json").
        "token"                 - Bearer token for authentiction.

	Notes:
    	- host_ip is the IP that will appear in DNS responses for managed hosts. 
    	  If not set, the server automatically detects a suitable host IP.
    	- dns_address is the interface the DNS server listens on. Can be 0.0.0.0:53
    	  to listen on all interfaces.
    	- update_period controls how often Docker containers are refreshed for new hosts.

    Example configuration:

ADMIN API
    The Admin API provides endpoints for managing hosts, aliases, targets, and
    retrieving the server version. All endpoints use HTTP and respond with JSON.
	When appending ?pretty to a request, the JSON returned will be pretty formatted 

LIST HOSTS
    GET /hosts
    Returns a JSON array of all registered hosts.
    
    Example:
        curl -H "Authorization: Bearer <token>" https://<server>/hosts

ADD HOST
    POST /hosts
    Adds a new host entry. You may optionally include aliases.

    Request body (JSON):
    {
        "name": "<host>",
        "aliases": ["<alias>"]
    }

    Example:
        curl -X POST -H "Content-Type: application/json" \
             -H "Authorization: Bearer <token>" \
             -d '{"name":"<host>","aliases":["<alias>"]}' \
             https://<server>/hosts

DELETE HOST
    DELETE /hosts/{hostname}
    Deletes the specified host and all associated aliases.

    Example:
        curl -X DELETE -H "Authorization: Bearer <token>" \
             https://<server>/hosts/<host>

ADD ALIAS
    POST /hosts/{hostname}/alias
    Adds a new alias to an existing host.

    Request body (JSON):
    {
        "alias": "<alias>"
    }

    Example:
        curl -X POST -H "Content-Type: application/json" \
             -H "Authorization: Bearer <token>" \
             -d '{"alias":"<alias>"}' \
             https://<server>/hosts/<host>/alias

LIST TARGETS
    GET /hosts/{hostname}/targets
    Lists all targets for a given host along with the currently active target.

    Response (JSON):
    {
        "name": "<host>",
        "active": 0,
        "targets": ["<ip:port1>", "<ip:port2>"]
    }

    Example:
        curl -H "Authorization: Bearer <token>" \
             https://<server>/hosts/<host>/targets

SET ACTIVE TARGET
    POST /hosts/{hostname}/target
    Sets the active target for a host.

    Request body (JSON):
    {
        "active_target": <target_index>
    }

    Example:
        curl -X POST -H "Content-Type: application/json" \
             -H "Authorization: Bearer <token>" \
             -d '{"active_target":<target_index>}' \
             https://<server>/hosts/<host>/target

GET DDP VERSION
    GET /version
    Returns the current version of the DDP server.

    Example:
        curl -H "Authorization: Bearer <token>" https://<server>/version

SEE ALSO
    ddpctl(1)

AUTHOR
       Written by pergus.
`

// -----------------------------------------------------------------------------
// Help Functions
// -----------------------------------------------------------------------------

func getHostIP() (string, error) {
	conn, err := net.Dial("udp", cfg.UpstreamDNS)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

func appendIfMissing(slice []string, s string) []string {
	if slices.Contains(slice, s) {
		return slice
	}
	return append(slice, s)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only check token if it's set
		if cfg.Token != "" {
			auth := r.Header.Get("Authorization")
			expected := "Bearer " + cfg.Token
			if auth != expected {
				http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

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

	// default update period if not set
	if cfg.UpdatePeriod <= 0 {
		cfg.UpdatePeriod = 10 // default 10 seconds
	}

	// detected HostIP if empty
	if cfg.HostIP == "" {
		ip, err := getHostIP()
		if err != nil {
			log.Printf("Failed to detect host IP, you should set host_ip in config: %v", err)
		} else {
			cfg.HostIP = ip
		}
	}
}

// -----------------------------------------------------------------------------
// Load Aliases
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// REST Admin API
// -----------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, data interface{}, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if _, ok := r.URL.Query()["pretty"]; ok {
		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			http.Error(w, fmt.Sprintf("JSON encoding error: %v", err), http.StatusInternalServerError)
			return
		}
		b = append(b, '\n')
		w.Write(b)
	} else {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			http.Error(w, fmt.Sprintf("JSON encoding error: %v", err), http.StatusInternalServerError)
		}
	}
}

func listHosts(w http.ResponseWriter, r *http.Request) {
	hostsLock.RLock()
	defer hostsLock.RUnlock()

	list := []*HostEntry{}
	for _, h := range hosts {
		list = append(list, h)
	}

	// Sort alphabetically
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })

	writeJSON(w, list, r)
}

func addHost(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var h HostEntry
	if err := json.NewDecoder(r.Body).Decode(&h); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if h.Name == "" {
		http.Error(w, "host name is required", http.StatusBadRequest)
		return
	}

	hostsLock.Lock()
	defer hostsLock.Unlock()

	if _, exists := hosts[h.Name]; exists {
		http.Error(w, "host already exists", http.StatusConflict)
		return
	}

	hosts[h.Name] = &h
	for _, alias := range h.Aliases {
		if _, exists := hosts[alias]; exists {
			http.Error(w, fmt.Sprintf("alias %s already exists", alias), http.StatusConflict)
			return
		}
		hosts[alias] = &h
	}

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, h, r)
}

func listTargets(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/hosts/")
	name = strings.TrimSuffix(name, "/targets")

	hostsLock.RLock()
	h, ok := hosts[name]
	hostsLock.RUnlock()

	if !ok {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}

	resp := map[string]interface{}{
		"name":    h.Name,
		"active":  h.ActiveTarget,
		"targets": h.Targets,
	}

	writeJSON(w, resp, r)
}

func setActiveTarget(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 4 || parts[3] != "target" {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	hostname := parts[2]

	var body struct {
		ActiveTarget int `json:"active_target"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hostsLock.Lock()
	defer hostsLock.Unlock()

	h, ok := hosts[hostname]
	if !ok {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}

	if body.ActiveTarget < 0 || body.ActiveTarget >= len(h.Targets) {
		http.Error(w, "invalid target index", http.StatusBadRequest)
		return
	}

	h.ActiveTarget = body.ActiveTarget

	// Respond with the updated host using writeJSON
	writeJSON(w, h, r)
}

func deleteHost(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/hosts/")

	hostsLock.Lock()
	defer hostsLock.Unlock()

	h, ok := hosts[name]
	if !ok {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}

	// Remove host and all its aliases
	delete(hosts, h.Name)
	for _, a := range h.Aliases {
		delete(hosts, a)
	}

	// Respond with deleted host info
	writeJSON(w, map[string]interface{}{
		"deleted": h.Name,
		"aliases": h.Aliases,
	}, r)
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
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}

	// Add alias if it doesn't exist and is not equal to h.Name
	if payload.Alias != h.Name {
		h.Aliases = appendIfMissing(h.Aliases, payload.Alias)
	}

	// Persist alias to disk
	saveAliasToFile(payload.Alias, hostname)

	// Respond with updated host entry
	writeJSON(w, h, r)
}

func adminManual(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(manual))
}

func version(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"ddp_version": ddpVersion,
	})
}

func startAdminAPI() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", adminManual)
	mux.HandleFunc("/version", version)
	mux.HandleFunc("/hosts", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			listHosts(w, r)
		case "POST":
			addHost(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	mux.HandleFunc("/hosts/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/alias") && r.Method == "POST":
			addAlias(w, r)
		case strings.HasSuffix(r.URL.Path, "/targets") && r.Method == "GET":
			listTargets(w, r)
		case strings.HasSuffix(r.URL.Path, "/target") && r.Method == "POST":
			setActiveTarget(w, r)
		case r.Method == "DELETE":
			deleteHost(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	log.Printf(
		"HTTPS Admin API running on %s protected: %v with cert=%s key=%s\n",
		cfg.AdminAddr,
		cfg.Token != "",
		cfg.CertFile,
		cfg.KeyFile,
	)
	log.Fatal(http.ListenAndServeTLS(cfg.AdminAddr, cfg.CertFile, cfg.KeyFile, mux))
}

// -----------------------------------------------------------------------------
// DNS Server
// -----------------------------------------------------------------------------

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
	server := &dns.Server{Addr: cfg.DNSAddr, Net: "udp"}
	log.Printf("DNS server running on %s", cfg.DNSAddr)
	log.Fatal(server.ListenAndServe())
}

// -----------------------------------------------------------------------------
// Docker Discovery
// -----------------------------------------------------------------------------

func startDockerWatcher(ctx context.Context) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("failed to create docker client: %v", err)
	}

	// helper to check if port is excluded
	portExcluded := func(port int) bool {
		return slices.Contains(cfg.ExcludedPorts, port)
	}

	addContainers := func() {
		containers, err := cli.ContainerList(ctx, container.ListOptions{})
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
				// add the target to the Targets array
				existing, ok := hosts[h.Name]
				if ok {
					existing.Targets = appendIfMissing(existing.Targets, target)
				} else {
					h.ActiveTarget = 0
					hosts[h.Name] = h
				}
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

// -----------------------------------------------------------------------------
// HTTPS Reverse Proxy
// -----------------------------------------------------------------------------

func reverseProxyHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	hostsLock.RLock()
	h, ok := hosts[host]
	hostsLock.RUnlock()
	if !ok || len(h.Targets) == 0 {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}

	idx := h.ActiveTarget
	if idx < 0 || idx >= len(h.Targets) {
		http.Error(w, "invalid active target", http.StatusInternalServerError)
		return
	}
	target := h.Targets[idx]

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

	log.Printf("HTTPS reverse proxy running on %s with cert=%s key=%s\n", cfg.ProxyAddr, cfg.CertFile, cfg.KeyFile)
	log.Fatal(http.ListenAndServeTLS(cfg.ProxyAddr, cfg.CertFile, cfg.KeyFile, mux))
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

func main() {
	configPath := flag.String("config", "config.json", "path to JSON config")
	flag.Parse()

	loadConfig(*configPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Printf("Starting Docker-DNS-Proxy version %v\n", ddpVersion)
	go startDNS()
	go startAdminAPI()
	go startDockerWatcher(ctx)

	// Give Docker watcher a chance to populate hosts before patching aliases
	time.Sleep(500 * time.Millisecond)
	loadAliases()

	startHTTPSServer()
}
