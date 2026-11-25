package sandbox

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestDockerRunsTheE2BSmokeScript runs the program E2B's smoke test stages in its
// microVM, as a project step the way E2B runs it, in the docker suite's locked-down
// container (guest_scripts_test.go lists every such program): it must print the report the
// smoke test parses, with node's version, the step's directory, and no egress open.
func TestDockerRunsTheE2BSmokeScript(t *testing.T) {
	requireDocker(t)
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := testDocker().RunProject(ctx, ProjectRequest{
		Files: []File{{Path: "plimsoll-smoke.cjs", Content: vmSmokeProbe}},
		Steps: []string{"node plimsoll-smoke.cjs"}, Timeout: 60 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		t.Fatalf("%s %q steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	var report struct {
		Node       string   `json:"node"`
		Cwd        string   `json:"cwd"`
		EgressOpen []string `json:"egressOpen"`
	}
	if err := json.Unmarshal([]byte(res.Steps[0].Stdout), &report); err != nil {
		t.Fatalf("unparseable report %q: %v", res.Steps[0].Stdout, err)
	}
	if report.Node == "" || report.Cwd != "/work" || len(report.EgressOpen) != 0 {
		t.Fatalf("report %+v", report)
	}
}

// e2bSmokeResponders answers, inside the docker stand-in's container, on loopback: an echo
// of any datagram on port 5353, a DNS server on UDP port 5354 and one on TCP port 5355 that
// answer every question with 127.0.0.1, each started when its name is an argument. With
// "-refuse" after a name, that responder answers every datagram or question with DNS code
// REFUSED and no answer instead, as Docker Cloud does under deny-all (measured
// 2026-11-24, finding release-106). It writes the file ready once they listen, and exits
// after 30 s.
const e2bSmokeResponders = `const dgram = require("node:dgram"), fs = require("node:fs"), net = require("node:net");
const want = process.argv.slice(2);
let up = 0;
const listening = () => { if (++up === want.length) fs.writeFileSync("ready", ""); };
const reply = (m, refuse) => {
  let i = 12;
  while (i < m.length && m[i] !== 0) i += m[i] + 1;
  return refuse
    ? Buffer.concat([m.subarray(0, 2), Buffer.from("81850001000000000000", "hex"), m.subarray(12, i + 5)])
    : Buffer.concat([m.subarray(0, 2), Buffer.from("81800001000100000000", "hex"), m.subarray(12, i + 5),
      Buffer.from("c00c000100010000003c00047f000001", "hex")]);
};
for (const name of want) {
  const refuse = name.endsWith("-refuse"), kind = name.replace(/-refuse$/, "");
  if (kind === "udp" || kind === "dns") {
    const s = dgram.createSocket("udp4");
    s.on("message", (m, r) => s.send(kind === "udp" && !refuse ? m : reply(m, refuse), r.port, r.address));
    s.bind(kind === "udp" ? 5353 : 5354, "127.0.0.1", listening);
  }
  if (kind === "tcpdns") {
    net.createServer((c) => {
      let got = Buffer.alloc(0);
      c.on("error", () => {});
      c.on("data", (d) => {
        got = Buffer.concat([got, d]);
        if (got.length < 2 || got.length < 2 + got.readUInt16BE(0)) return;
        const r = reply(got.subarray(2, 2 + got.readUInt16BE(0)), refuse);
        c.end(Buffer.concat([Buffer.from([r.length >> 8, r.length & 255]), r]));
      });
    }).listen(5355, "127.0.0.1", listening);
  }
}
setTimeout(() => process.exit(0), 30000);
`

// TestDockerE2BSmokeScriptCountsUDPAndDNS: the E2B smoke script counts a UDP datagram that
// is answered, a DNS question over TCP that is answered, and an outside resolver that
// answers, as egress, each on its own (finding release-69), and counts none of them when
// every answer is a refusal, Docker Cloud's answer under deny-all (finding release-106). It
// runs the script as TestDockerRunsTheE2BSmokeScript does, with its three targets pointed
// at loopback responders in the same container (the container has no network, so nothing
// else could answer); the four fetches find nothing, as there.
func TestDockerE2BSmokeScriptCountsUDPAndDNS(t *testing.T) {
	requireDocker(t)
	t.Parallel()
	probe := strings.Replace(vmSmokeProbe, `const udpTarget = ["8.8.8.8", 53];`, `const udpTarget = ["127.0.0.1", 5353];`, 1)
	probe = strings.Replace(probe, `const tcpTarget = ["8.8.8.8", 53];`, `const tcpTarget = ["127.0.0.1", 5355];`, 1)
	probe = strings.Replace(probe, `const dnsServer = "1.1.1.1";`, `const dnsServer = "127.0.0.1:5354";`, 1)
	if strings.Count(probe, "127.0.0.1") != 3 {
		t.Fatal("the smoke script no longer sets its UDP target, TCP target and resolver on lines of their own; update this test's substitution")
	}
	// Docker's built-in seccomp profile, not the shipped one the suite otherwise applies: the
	// shipped profile refuses every UDP socket (docs/seccomp.md), so under it the responders
	// cannot listen and the probe cannot send, and the case would prove nothing. E2B's guest
	// applies no such profile.
	d := testDocker()
	d.Seccomp = ""
	for _, c := range []struct {
		responders string
		want       []string
	}{
		{"udp tcpdns dns", []string{"udp://127.0.0.1:5353", "tcp-dns://127.0.0.1:5355", "dns://127.0.0.1:5354"}},
		{"udp", []string{"udp://127.0.0.1:5353"}},
		{"tcpdns", []string{"tcp-dns://127.0.0.1:5355"}},
		{"dns", []string{"dns://127.0.0.1:5354"}},
		{"udp-refuse tcpdns-refuse dns-refuse", nil},
		{"udp-refuse dns", []string{"dns://127.0.0.1:5354"}},
	} {
		t.Run(c.responders, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			step := "node responders.js " + c.responders + " >responders.log 2>&1 </dev/null &\n" +
				"i=0; while [ ! -e ready ] && [ $i -lt 200 ]; do i=$((i+1)); sleep 0.05; done\nnode plimsoll-smoke.cjs"
			res, err := d.RunProject(ctx, ProjectRequest{
				Files: []File{{Path: "plimsoll-smoke.cjs", Content: probe}, {Path: "responders.js", Content: e2bSmokeResponders}},
				Steps: []string{step}, Timeout: 60 * time.Second, Artifacts: []string{"responders.log"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
				t.Fatalf("%s %q steps %+v", res.Outcome, res.Detail, res.Steps)
			}
			var report struct {
				EgressOpen []string `json:"egressOpen"`
			}
			if err := json.Unmarshal([]byte(res.Steps[0].Stdout), &report); err != nil {
				t.Fatalf("unparseable report %q: %v", res.Steps[0].Stdout, err)
			}
			if !slices.Equal(report.EgressOpen, c.want) {
				var log []byte
				if len(res.Artifacts) == 1 {
					log = res.Artifacts[0].Content
				}
				t.Fatalf("egress open %q with %s answering; want %q (the responders wrote %q)", report.EgressOpen, c.responders, c.want, log)
			}
		})
	}
}
