package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
)

var adminURL string

type HostEntry struct {
	Name         string   `json:"name"`
	Url          string   `json:"url"`
	Targets      []string `json:"targets"`
	ActiveTarget int      `json:"active_targte"`
	Aliases      []string `json:"aliases,omitempty"`
}

var help = `
DDPCTL(1)                    USER COMMANDS                    DDPCTL(1)

NAME
       ddpctl - Command-line administration tool for docker-dns-proxy

SYNOPSIS
       ddpctl [--url <admin-api-url>] <command> [arguments]

DESCRIPTION
       ddpctl is the administrative CLI for docker-dns-proxy. It allows users
       to list, add, and remove hosts, manage aliases, view and set active
       targets, and check the server version. All commands communicate with
       the Admin API of a running ddp instance.

ADMIN API URL
       By default, ddpctl uses http://localhost:6060. You can override it
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
       If no aliases are provided, only the main host is created.

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

   help
       Display this help text.

SEE ALSO
       ddp(1) - docker-dns-proxy server
`

func main() {
	rootCmd := &cobra.Command{
		Use:   "ddptl",
		Short: "Admin CLI for docker-dns-proxy",
		Long:  "Control the docker-dns-proxy",
	}

	rootCmd.PersistentFlags().StringVar(&adminURL, "url", "http://localhost:6060", "Admin API URL")

	// list command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List all hosts",
		Run: func(cmd *cobra.Command, args []string) {
			listHosts()
		},
	})

	// add host command
	addCmd := &cobra.Command{
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
	}
	rootCmd.AddCommand(addCmd)

	// delete host command
	delCmd := &cobra.Command{
		Use:   "delete [name]",
		Short: "Delete a host",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			deleteHost(args[0])
		},
	}
	rootCmd.AddCommand(delCmd)

	// add alias command
	aliasCmd := &cobra.Command{
		Use:   "alias [host] [alias]",
		Short: "Add an alias to an existing host",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			addAlias(args[0], args[1])
		},
	}
	rootCmd.AddCommand(aliasCmd)

	// list targets for all hosts
	rootCmd.AddCommand(&cobra.Command{
		Use:   "list-targets",
		Short: "List all targets for all hosts",
		Run: func(cmd *cobra.Command, args []string) {
			listAllTargets()
		},
	})

	// list targets for specific host
	rootCmd.AddCommand(&cobra.Command{
		Use:   "targets [host]",
		Short: "List all targets for a specific host",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			listTargets(args[0])
		},
	})

	// set active target
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
			fmt.Println(help)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Show ddp server version",
		Run: func(cmd *cobra.Command, args []string) {
			resp, err := http.Get(adminURL + "/version")
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			defer resp.Body.Close()

			var v map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
				fmt.Println("Error decoding response:", err)
				return
			}

			fmt.Println("ddp server version:", v["ddp_version"])
		},
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// ---------------- Admin API calls ----------------

func listHosts() {
	resp, err := http.Get(adminURL + "/hosts")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	var hosts []HostEntry
	if err := json.NewDecoder(resp.Body).Decode(&hosts); err != nil {
		fmt.Println("Error decoding response:", err)
		return
	}

	// Sort hosts by name
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].Name < hosts[j].Name
	})

	// Pretty print table using go-pretty
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
		t.AppendRow(table.Row{
			h.Name,
			h.Url,
			target,
			aliasStr,
		})
	}
	t.Style().Format.Header = text.FormatDefault
	t.Render()
}

func addHost(name string, aliases []string) {
	body := map[string]interface{}{
		"name":    name,
		"aliases": aliases,
	}
	postJSON("/hosts", body)
}

func deleteHost(name string) {
	req, _ := http.NewRequest("DELETE", adminURL+"/hosts/"+name, nil)
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
	postJSON(fmt.Sprintf("/hosts/%s/alias", host), body)
}

func listAllTargets() {
	resp, err := http.Get(adminURL + "/hosts")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	var hosts []HostEntry
	if err := json.NewDecoder(resp.Body).Decode(&hosts); err != nil {
		fmt.Println("Error decoding response:", err)
		return
	}

	// Sort hosts alphabetically
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
	resp, err := http.Get(adminURL + "/hosts/" + host + "/targets")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Error: %s\n", strings.TrimSpace(string(body)))
		return
	}

	var h struct {
		Name    string   `json:"name"`
		Active  int      `json:"active"`
		Targets []string `json:"targets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		fmt.Println("Error decoding response:", err)
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

	resp, err := http.Post(adminURL+"/hosts/"+host+"/target", "application/json", bytes.NewReader(b))
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

	// Decode response to verify active target
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
	// Success: do nothing if ActiveTarget matches
}

func postJSON(path string, data interface{}) {
	b, _ := json.Marshal(data)
	resp, err := http.Post(adminURL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(os.Stdout, resp.Body)
	fmt.Println()
}
