package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
)

type HostEntry struct {
	Name         string   `json:"name"`
	Url          string   `json:"url"`
	Targets      []string `json:"targets"`
	ActiveTarget int      `json:"active_target"`
	Aliases      []string `json:"aliases,omitempty"`
}

type Config struct {
	AdminURL string `json:"admin_url"`
	Token    string `json:"token"`
}

var (
	cfg        Config
	configFile string

	defaultAdminURL = "https://localhost:6060"
)

var manual = `
DDPCTL(1)                    USER COMMANDS                    DDPCTL(1)

NAME
       ddpctl - Command-line administration tool for docker-dns-proxy

SYNOPSIS
       ddpctl [--url <admin-api-url>] [--token <token>] [--config <file>] <command> [arguments]

DESCRIPTION
       ddpctl is the administrative CLI for docker-dns-proxy. It allows users
       to list, add, and remove hosts, manage aliases, view and set active
       targets, and check the server version. All commands communicate with
       the Admin API of a running ddp instance.

CONFIGURATION FILE
       You can store the admin API URL and bearer token in a JSON configuration file
       and pass it with the --config flag. Values in the configuration file are
       used only if the corresponding command-line flags (--url, --token) are not provided.

       Example configuration file (config.json):
       
       {
           "admin_url": "https://dev.z90.org:5880",
           "token":     "ThisIsASecretToken"
       }

ADMIN API URL
       By default, ddpctl uses https://localhost:6060. You can override it
       using:

           --url <admin-api-url>

COMMANDS

   list
       List all hosts registered in docker-dns-proxy. Displays the host name,
       main URL, current active target, and any aliases.

       Example:
           ddpctl --url http://<server>:6060 list

   add [name] [aliases]
       Add a host with optional comma-separated aliases. Aliases are optional.

       Example:
           ddpctl add service.domain.org alias1.domain.org,alias2.domain.org

   delete [name]
       Remove a host and all its aliases.

       Example:
           ddpctl delete service.domain.org

   alias [host] [alias]
       Add a new alias to an existing host.

       Example:
           ddpctl alias service.domain.org alias-main.domain.org

   list-targets
       List all targets for all hosts. The active target for each host is
       indicated with an asterisk (*) in the "ACTIVE" column.

       Example:
           ddpctl list-targets

   targets [host]
       List all targets for a specific host, showing the active target.

       Example:
           ddpctl targets service.domain.org

   set-target [host] [index]
       Set the active target index for a host. The index corresponds to the
       position of the target in the host's target list.

       Example:
           ddpctl set-target service.domain.org 1

   version
       Show the running ddp server version.

       Example:
           ddpctl version

   manual
       Display this help text.

SEE ALSO
       ddp(1) - docker-dns-proxy server
`

// global client
var client *http.Client

func initHTTPClient(skipVerify bool) {
	// skipVerify=true only for self-signed or dev certs
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}
	client = &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}
}

func GetPager() string {
	// Check if "less" is available
	_, err := exec.LookPath("less")
	if err == nil {
		return "less"
	}

	// Fallback to "more" if "less" is not available
	_, err = exec.LookPath("more")
	if err == nil {
		return "more"
	}

	// If no pager is available, return an empty string
	return ""
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "ddpctl",
		Short: "Admin CLI for docker-dns-proxy",
		Long:  "Control the docker-dns-proxy",
	}

	rootCmd.PersistentFlags().StringVar(&cfg.AdminURL, "url", defaultAdminURL, "Admin API URL")
	rootCmd.PersistentFlags().StringVar(&cfg.Token, "token", "", "Bearer token for admin API")
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "config.json", "Optional config file with admin_url and token")

	cobra.OnInitialize(func() {
		if _, err := os.Stat(configFile); err == nil {
			loadConfigFile(configFile)
		}
	})

	initHTTPClient(true)

	// commands
	rootCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List all hosts",
		Run: func(cmd *cobra.Command, args []string) {
			listHosts()
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "add [name] [aliases]",
		Short: "Add a host with optional comma-separated aliases",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			name := args[0]
			aliases := []string{}
			if len(args) > 1 {
				aliases = strings.Split(args[1], ",")
			}
			addHost(name, aliases)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "delete [name]",
		Short: "Delete a host",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			deleteHost(args[0])
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "alias [host] [alias]",
		Short: "Add an alias to an existing host",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			addAlias(args[0], args[1])
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "list-targets",
		Short: "List all targets for all hosts",
		Run: func(cmd *cobra.Command, args []string) {
			listAllTargets()
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "targets [host]",
		Short: "List all targets for a specific host",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			listTargets(args[0])
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "set-target [host] [index]",
		Short: "Set active target index for a host",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			idx, err := strconv.Atoi(args[1])
			if err != nil {
				fmt.Println("Invalid index:", args[1])
				return
			}
			setActiveTarget(args[0], idx)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "manual",
		Short: "Show the manual page",
		Run: func(cmd *cobra.Command, args []string) {
			// Use a pager if available; otherwise, fallback to direct output
			pager := GetPager()
			if pager == "" {
				fmt.Println(manual)
				return
			}

			// Set up the pager command
			command := exec.Command(pager)
			command.SysProcAttr = &syscall.SysProcAttr{Foreground: true} // Creates a new process group
			command.Stdin = bytes.NewReader([]byte(manual))
			command.Stdout = os.Stdout
			command.Stderr = os.Stderr

			// Run the pager and handle errors
			err := command.Start()
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: running pager failed: %v\n", err)
				fmt.Println(manual) // Fallback to printing the text if the pager fails
			}

			err = command.Wait()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: pager failed: %v\n", err)
			}

		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Show ddp server version",
		Run: func(cmd *cobra.Command, args []string) {
			var v map[string]string
			if err := getJSON("/version", &v); err != nil {
				fmt.Println("Error:", err)
				return
			}
			fmt.Println("ddp server", cfg.AdminURL, "version:", v["ddp_version"])
		},
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

func loadConfigFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading config file:", err)
		return
	}
	var fileCfg Config
	if err := json.Unmarshal(data, &fileCfg); err != nil {
		fmt.Println("Error parsing config file:", err)
		return
	}

	// Only set values from file if not already set via flags
	if fileCfg.AdminURL != "" && fileCfg.AdminURL != defaultAdminURL {
		cfg.AdminURL = fileCfg.AdminURL
	}
	if cfg.Token == "" {
		cfg.Token = fileCfg.Token
	}
}

// -----------------------------------------------------------------------------
// HTTP Helpers
// -----------------------------------------------------------------------------

func makeRequest(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, cfg.AdminURL+path, body)
	if err != nil {
		return nil, err
	}
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	if method == http.MethodPost || method == http.MethodPut {
		req.Header.Set("Content-Type", "application/json")
	}

	return req, nil
}

func getJSON(path string, result interface{}) error {
	req, err := makeRequest(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error: %s", strings.TrimSpace(string(data)))
	}
	if result != nil {
		return json.NewDecoder(resp.Body).Decode(result)
	}
	return nil
}

func postJSON(path string, data interface{}) {
	b, _ := json.Marshal(data)
	req, err := makeRequest(http.MethodPost, path, bytes.NewReader(b))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(os.Stdout, resp.Body)
	fmt.Println()
}

// -----------------------------------------------------------------------------
// Admin API calls
// -----------------------------------------------------------------------------

func listHosts() {
	var hosts []HostEntry
	if err := getJSON("/hosts", &hosts); err != nil {
		fmt.Println(err)
		return
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleRounded)
	t.AppendHeader(table.Row{"NAME", "URL", "TARGET", "ALIASES"})
	for _, h := range hosts {
		aliasStr := ""
		if len(h.Aliases) > 0 {
			aliasStr = "https://" + strings.Join(h.Aliases, ", ")
		}
		target := ""
		if h.ActiveTarget >= 0 && h.ActiveTarget < len(h.Targets) {
			target = h.Targets[h.ActiveTarget]
		}
		t.AppendRow(table.Row{h.Name, h.Url, target, aliasStr})
	}
	t.Style().Format.Header = text.FormatDefault
	t.Render()
}

func addHost(name string, aliases []string) {
	body := map[string]interface{}{"name": name, "aliases": aliases}
	postJSON("/hosts", body)
}

func deleteHost(name string) {
	req, _ := makeRequest(http.MethodDelete, "/hosts/"+name, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	fmt.Println("Deleted", name, "status:", resp.Status)
}

func addAlias(host, alias string) {
	body := map[string]string{"alias": alias}
	postJSON("/hosts/"+host+"/alias", body)
}

func listAllTargets() {
	var hosts []HostEntry
	if err := getJSON("/hosts", &hosts); err != nil {
		fmt.Println(err)
		return
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleRounded)
	t.AppendHeader(table.Row{"HOST", "INDEX", "ACTIVE", "TARGET"})

	for _, h := range hosts {
		for i, target := range h.Targets {
			hostName := ""
			if i == 0 {
				hostName = h.Name
			}
			active := ""
			if i == h.ActiveTarget {
				active = "*"
			}
			t.AppendRow(table.Row{hostName, i, active, target})
		}
	}
	t.Style().Format.Header = text.FormatDefault
	t.Render()
}

func listTargets(host string) {
	var h struct {
		Name    string   `json:"name"`
		Active  int      `json:"active"`
		Targets []string `json:"targets"`
	}
	if err := getJSON("/hosts/"+host+"/targets", &h); err != nil {
		fmt.Println(err)
		return
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleRounded)
	t.AppendHeader(table.Row{"INDEX", "ACTIVE", "TARGET"})
	for i, target := range h.Targets {
		active := ""
		if i == h.Active {
			active = "*"
		}
		t.AppendRow(table.Row{i, active, target})
	}
	t.Style().Format.Header = text.FormatDefault
	t.Render()
}

func setActiveTarget(host string, index int) {
	body := map[string]int{"active_target": index}
	b, _ := json.Marshal(body)
	req, err := makeRequest(http.MethodPost, "/hosts/"+host+"/target", bytes.NewReader(b))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		fmt.Printf("Error: %s\n", strings.TrimSpace(string(data)))
		return
	}

	var h struct {
		Name         string   `json:"name"`
		ActiveTarget int      `json:"active_target"`
		Targets      []string `json:"targets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		fmt.Println("Error decoding response:", err)
		return
	}

	if h.ActiveTarget != index {
		fmt.Printf("Warning: active target not set as requested. Current active: %d\n", h.ActiveTarget)
	}
	// success: do nothing if matches
}
