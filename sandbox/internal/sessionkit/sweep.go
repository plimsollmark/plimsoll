// Package sessionkit holds what every session provider runs inside its sandbox to
// keep the boundary between calls: the process lister that records a fresh
// sandbox's own processes, the sweep that runs after every call, and the
// interpreters a session may keep alive between calls (interp.go). The programs
// are node scripts passed in argv, so a provider needs nothing in its image beyond
// node and sh, and a leftover process cannot append to a script read from stdin.
// Each provider supplies only its exec and its own lifecycle (stop and start,
// pause and unpause).
//
// What makes the sweep's verdict trustworthy, measured on 2026-09-28 against an
// OpenShell v0.1.2 gateway (private/openshell-sessions-plan-2026-09-28.md):
//
//   - A process a call starts outlives the call: a cancelled exec kills at most the
//     command's process group, and a normal exit kills nothing. The sweep kills every
//     process except the sandbox's own (PID 1 and the main process, recorded when the
//     sandbox became ready by PID, start time and command line), the processes the
//     session keeps on purpose (live interpreters), its own ancestors and itself, by
//     PID, until a scan finds none.
//   - A process is alive while any of its threads is, not while its /proc entry says
//     so: a main thread that called pthread_exit leaves the entry a zombie with its
//     other threads running.
//   - The verdict is the sweep's exit status alone, which code in the sandbox cannot
//     forge without attaching to it. The provider prevents that: openshell refuses a
//     host whose Yama ptrace_scope would allow it, and docker runs the sweep
//     non-dumpable under the runner guard.
package sessionkit

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Sweep exit statuses; any other status, or no status, means the boundary is unproven.
const (
	SweepClean        = 0  // no process but the sandbox's own and the kept ones; disk within budget
	SweepOverBudget   = 10 // clean, but the session's files exceed the budget
	SweepUnmeasurable = 11 // clean, but a directory could not be read
)

// MaxDiskEntries bounds the sweep's walk of the session's directories: past it the
// session counts as over its disk budget, since a walk of every entry must stay
// bounded.
const MaxDiskEntries = 200000

// liveFn is the liveness test both scripts use. A process whose main thread called
// pthread_exit shows in /proc as a zombie while its other threads run on (measured
// 2026-09-28 on the runner image's base), so a state of Z or X on the entry itself
// proves nothing: every thread under task/ must be dead before the process is. A
// true zombie (every thread dead) is left alone, because killing one does nothing
// and the sweep would never converge.
const liveFn = `function live(d){try{for(const t of fs.readdirSync("/proc/"+d+"/task")){
const st=fs.readFileSync("/proc/"+d+"/task/"+t+"/stat","latin1");
const s=st.slice(st.lastIndexOf(")")+2).split(" ")[0];if(s!=="Z"&&s!=="X")return true}}catch{return false}return false}
`

// ListScript lists every process except itself and its ancestors, and reads the
// host's Yama ptrace_scope, as JSON on stdout. Its output is trusted only where no
// call's code can have run: in a sandbox just created or just started, or right
// after a clean sweep when no interpreter is alive.
const ListScript = liveFn + `const fs=require("fs");const self=String(process.pid);const skip=new Set([self]);
for(let p=self;;){let st;try{st=fs.readFileSync("/proc/"+p+"/stat","latin1")}catch{break}
const pp=st.slice(st.lastIndexOf(")")+2).split(" ")[1];if(!pp||pp==="0"||skip.has(pp))break;skip.add(pp);p=pp}
const procs=[];for(const d of fs.readdirSync("/proc")){if(!/^[0-9]+$/.test(d)||(skip.has(d)&&d!=="1")||!live(d))continue;
try{const st=fs.readFileSync("/proc/"+d+"/stat","latin1");const f=st.slice(st.lastIndexOf(")")+2).split(" ");
const raw=fs.readFileSync("/proc/"+d+"/cmdline","latin1");const cmd=raw.split("\0").join(" ").trim();
procs.push({pid:+d,ppid:+f[1],state:f[0],start:f[19],cmd,cmdHex:Buffer.from(raw,"latin1").toString("hex")})}catch{}}
let ptrace="";try{ptrace=fs.readFileSync("/proc/sys/kernel/yama/ptrace_scope","latin1").trim()}catch{}
process.stdout.write(JSON.stringify({ptrace,procs}))`

// SweepScript kills every process that is not kept, not an ancestor and not itself,
// until a scan finds none, then walks the session's directories. Arguments: the disk
// budget in bytes (0 = none), the entry bound, the directories to measure (joined by
// commas), then the identities to keep (pid:starttime:cmdline-hex, so a process that
// lands on a kept PID in the same clock tick is kept only if its command line matches
// too). Its exit status is the verdict (the Sweep* constants); its stdout is a summary
// for the log only.
const SweepScript = liveFn + `const fs=require("fs");const [budget,maxEntries,dirList,...keepList]=process.argv.slice(1);
const keep=new Set(keepList);const self=String(process.pid);const up=new Set([self]);
for(let p=self;;){let st;try{st=fs.readFileSync("/proc/"+p+"/stat","latin1")}catch{break}
const pp=st.slice(st.lastIndexOf(")")+2).split(" ")[1];if(!pp||pp==="0"||up.has(pp))break;up.add(pp);p=pp}
const nap=()=>Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,20);
function others(){const o=[];for(const d of fs.readdirSync("/proc")){if(!/^[0-9]+$/.test(d)||up.has(d))continue;
let st;try{st=fs.readFileSync("/proc/"+d+"/stat","latin1")}catch{continue}
const f=st.slice(st.lastIndexOf(")")+2).split(" ");if(!live(d))continue;
let cmd="";try{cmd=fs.readFileSync("/proc/"+d+"/cmdline").toString("hex")}catch{}
if(!keep.has(d+":"+f[19]+":"+cmd))o.push(+d)}return o}
let rounds=0,killed=0;
for(let o=others();o.length>0;o=others()){if(++rounds>50)process.exit(1);
for(const p of o){try{process.kill(p,"SIGKILL");killed++}catch{}}nap()}
let bytes=0,entries=0;const dirs=dirList.split(",").filter(Boolean);
while(dirs.length>0){const dir=dirs.pop();let names;
try{names=fs.readdirSync(dir)}catch{try{fs.chmodSync(dir,0o700);names=fs.readdirSync(dir)}catch{process.exit(11)}}
for(const n of names){const p=dir+"/"+n;let st;try{st=fs.lstatSync(p)}catch{continue}
if(++entries>+maxEntries)process.exit(10);bytes+=st.blocks*512;if(+budget>0&&bytes>+budget)process.exit(10);
if(st.isDirectory())dirs.push(p)}}
process.stdout.write(JSON.stringify({rounds,killed,bytes,entries}))`

// ListArgv is the lister's command line.
func ListArgv() []string { return []string{"node", "-e", ListScript} }

// SweepArgv is the sweep's command line: the disk budget, the directories it
// measures, and every process identity to keep.
func SweepArgv(diskBytes int64, dirs []string, keep []string) []string {
	return append([]string{"node", "-e", SweepScript, strconv.FormatInt(diskBytes, 10),
		strconv.Itoa(MaxDiskEntries), strings.Join(dirs, ",")}, keep...)
}

// Process is one entry of the lister's output.
type Process struct {
	PID    int    `json:"pid"`
	PPID   int    `json:"ppid"`
	State  string `json:"state"`
	Start  string `json:"start"`
	Cmd    string `json:"cmd"`
	CmdHex string `json:"cmdHex"` // the raw command line, NUL separators included
}

// Identity is the form the sweep keeps a process by.
func (p Process) Identity() string {
	return strconv.Itoa(p.PID) + ":" + p.Start + ":" + p.CmdHex
}

// Listing is the lister's output.
type Listing struct {
	Ptrace string    `json:"ptrace"`
	Procs  []Process `json:"procs"`
}

// ParseListing decodes the lister's stdout.
func ParseListing(stdout []byte) (Listing, error) {
	var l Listing
	if err := json.Unmarshal(stdout, &l); err != nil {
		return Listing{}, fmt.Errorf("the process list is not JSON: %w", err)
	}
	return l, nil
}

// Baseline reads the lister's output from a sandbox no call has touched and returns
// the identities of its own processes, which every sweep keeps. It refuses anything
// but PID 1 and one main process (a child of PID 1) running main. With
// requirePtrace it also refuses a host whose ptrace_scope is missing or 0: there,
// code in the sandbox could attach to the sweep and forge its exit status.
func Baseline(stdout []byte, main []string, requirePtrace bool) ([]string, error) {
	l, err := ParseListing(stdout)
	if err != nil {
		return nil, err
	}
	if requirePtrace {
		if scope, err := strconv.Atoi(l.Ptrace); err != nil || scope < 1 {
			return nil, fmt.Errorf("the host's kernel.yama.ptrace_scope reads %q; sessions need 1 or more, since at 0 code in the sandbox could attach to the sweep that ends each call and forge its verdict", l.Ptrace)
		}
	}
	var keep []string
	mains := 0
	want := strings.Join(main, " ")
	for _, pr := range l.Procs {
		switch {
		case pr.PID == 1:
		case pr.PPID == 1 && pr.Cmd == want:
			mains++
		default:
			return nil, fmt.Errorf("an untouched sandbox runs an unexpected process: pid %d ppid %d %q", pr.PID, pr.PPID, pr.Cmd)
		}
		keep = append(keep, pr.Identity())
	}
	if mains != 1 || len(keep) != 2 {
		return nil, fmt.Errorf("an untouched sandbox runs %d processes, %d of them the main process; want PID 1 and one main process", len(keep), mains)
	}
	return keep, nil
}
