package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
)

var adminURL string

type HostEntry struct {
	Name    string   `json:"name"`
	Url     string   `json:"url"`
	Targets []string `json:"targets"`
	Aliases []string `json:"aliases,omitempty"`
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "ddptl",
		Short: "Admin CLI for docker-dns-proxy",
		Long:  "Manage your docker-dns-proxy",
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
	t.AppendHeader(table.Row{"NAME", "URL", "TARGETS", "ALIASES"})
	for _, h := range hosts {
		aliasStr := ""
		if len(h.Aliases) > 0 {
			aliasStr = "https://" + strings.Join(h.Aliases, ", ")
		}

		t.AppendRow(table.Row{
			h.Name,
			h.Url,
			strings.Join(h.Targets, ", "),
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
