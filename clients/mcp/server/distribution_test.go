package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/clients/mcp/internal/fakedaemon"
	"github.com/plimsollmark/plimsoll/clients/mcp/server"
)

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

type setting struct {
	Sensitive bool   `json:"sensitive"`
	Default   string `json:"default"`
}

// The plugin, the server it pins and the Desktop bundle state one version, hand the
// server the same settings, and list the tools it registers.
func TestDistributionFilesAgree(t *testing.T) {
	var plugin struct {
		Name       string             `json:"name"`
		Version    string             `json:"version"`
		UserConfig map[string]setting `json:"userConfig"`
	}
	var mcpJSON struct {
		MCPServers map[string]struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env"`
		} `json:"mcpServers"`
	}
	var bundle struct {
		Version string `json:"version"`
		Server  struct {
			MCPConfig struct {
				Env map[string]string `json:"env"`
			} `json:"mcp_config"`
		} `json:"server"`
		Tools      []struct{ Name string } `json:"tools"`
		UserConfig map[string]setting      `json:"user_config"`
	}
	var market struct {
		Plugins []struct{ Name, Source string } `json:"plugins"`
	}
	readJSON(t, "../marketplace/plimsoll/.claude-plugin/plugin.json", &plugin)
	readJSON(t, "../marketplace/plimsoll/.mcp.json", &mcpJSON)
	readJSON(t, "../mcpb/manifest.json", &bundle)
	readJSON(t, "../marketplace/.claude-plugin/marketplace.json", &market)

	if plugin.Version != server.Version || bundle.Version != server.Version {
		t.Errorf("versions: server %s, plugin %s, bundle %s", server.Version, plugin.Version, bundle.Version)
	}
	entry := mcpJSON.MCPServers["plimsoll"]
	// The plugin starts its own launcher, which installs the pinned version into the
	// plugin's data directory; npx from the project directory could run the project's.
	if want := []string{"${CLAUDE_PLUGIN_ROOT}/launch.mjs"}; entry.Command != "node" || !slices.Equal(entry.Args, want) {
		t.Errorf("the plugin runs %s %v, want node %v", entry.Command, entry.Args, want)
	}
	launch, err := os.ReadFile("../marketplace/plimsoll/launch.mjs")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(launch), `const VERSION = "`+server.Version+`";`) {
		t.Errorf("the plugin's launcher does not pin version %s", server.Version)
	}
	if fmt.Sprint(entry.Env) != fmt.Sprint(bundle.Server.MCPConfig.Env) {
		t.Errorf("the plugin hands the server %v, the bundle %v", entry.Env, bundle.Server.MCPConfig.Env)
	}
	if fmt.Sprint(plugin.UserConfig) != fmt.Sprint(bundle.UserConfig) {
		t.Errorf("settings differ: plugin %v, bundle %v", plugin.UserConfig, bundle.UserConfig)
	}
	var launcher struct {
		Name     string            `json:"name"`
		Version  string            `json:"version"`
		Optional map[string]string `json:"optionalDependencies"`
	}
	readJSON(t, "../npm/package.json", &launcher)
	if launcher.Name != "@plimsollmark/mcp" || launcher.Version != server.Version || len(launcher.Optional) != 5 {
		t.Errorf("the npm launcher: %+v", launcher)
	}
	for name, v := range launcher.Optional {
		if v != server.Version {
			t.Errorf("the launcher pins %s at %s, not %s", name, v, server.Version)
		}
	}
	if len(market.Plugins) != 1 || market.Plugins[0].Name != plugin.Name || market.Plugins[0].Source != "./plimsoll" {
		t.Errorf("marketplace: %+v", market.Plugins)
	}

	c := connect(t, local(fakedaemon.DownURL(t)))
	list, err := c.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var registered, listed []string
	for _, tool := range list.Tools {
		registered = append(registered, tool.Name)
	}
	for _, tool := range bundle.Tools {
		listed = append(listed, tool.Name)
	}
	slices.Sort(registered)
	slices.Sort(listed)
	if !slices.Equal(registered, listed) {
		t.Errorf("the bundle lists %v, the server registers %v", listed, registered)
	}
}
