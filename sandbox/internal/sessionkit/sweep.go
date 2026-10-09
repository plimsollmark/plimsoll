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
// OpenShell v0.1.2 gateway:
//
//   - A process a call starts outlives the call: a cancelled exec kills at most the
//     command's process group, and a normal exit kills nothing. The sweep kills every
//     process except the sandbox's own (PID 1 and the main process, recorded when the
//     sandbox became ready by PID, start time and command line), the processes the
//     session keeps on purpose (live interpreters), its own ancestors and itself, by
//     PID, until a scan finds none.
//   - A process is alive while any of its threads is, not while its /proc entry says
//     so: a main thread that called pthread_exit leaves the entry a zombie with its
//     other threads running. A read that does not answer is never taken for death:
//     only the kernel saying a process does not exist ends it for the scan, and a
//     process that stays unreadable, or that cannot be killed, makes the verdict a
//     failure (clearFn; round-4, round-5 and round-6 reviews, 2026-10-08).
//   - In a virtual machine (E2B) /proc also shows the kernel's own threads, which
//     ignore SIGKILL and come and go on their own; every script skips them by their
//     PF_KTHREAD flag, which no user process can set. A container shows none.
//   - The verdict is the sweep's exit status alone, which code in the sandbox cannot
//     forge without attaching to it. The provider prevents that: openshell refuses a
//     host whose Yama ptrace_scope would allow it, and docker runs the sweep
//     non-dumpable under the runner guard.
package sessionkit

import (
	"encoding/json"
	"errors"
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

// QuiesceClean is the quiesce's exit status when every process of the session is
// stopped or gone. Any other status, or no status, means it is not, which is a
// boundary the sweep's own statuses do not cover: the call must not start.
const QuiesceClean = 0

// MaxDiskEntries bounds the sweep's walk of the session's directories: past it the
// session counts as over its disk budget, since a walk of every entry must stay
// bounded.
const MaxDiskEntries = 200000

// clearFn is what the quiesce and the sweep share: the liveness test and the kill
// loop. Both ran their own copy of the loop, and both skipped a process their
// liveness test could not answer for, which left it unkilled and the round clean
// (round-5 review, 2026-10-08).
//
//   - A process whose main thread called pthread_exit shows in /proc as a zombie while
//     its other threads run on (measured 2026-09-28 on the runner image's base), so a
//     state of Z or X on the entry itself proves nothing: every thread under task/ must
//     read dead before the process does.
//   - Not every read answers, and only one answer proves a process gone: the kernel
//     saying it does not exist (ENOENT, ESRCH). Any other failure to read a process's
//     stat, command line, thread list or a thread's state (ENOMEM is possible there)
//     leaves it unresolved, and an unresolved process keeps the loop going: it is
//     tried again next round, and if it stays unresolved for the whole bound the
//     verdict is a failure, never clean (round-6 review, 2026-10-08).
//   - Every process that is not kept is killed whatever its liveness reads, since a
//     thread created after the listing is invisible to that read. A process counts as
//     signalled, by the identity it was read under (PID and start time), only once
//     the kill succeeded or the kernel said it was gone; a kill refused for
//     permission leaves it unresolved, so it can end the verdict only as a failure.
//   - A true zombie (every thread read, every one dead) ends the loop, but only after
//     it has been signalled, so a process misread as one is killed before any round
//     can be called clean.
const clearFn = `function kthread(f){return (Number(f[6])&0x200000)!==0}
function gone(e){return !!e&&(e.code==="ENOENT"||e.code==="ESRCH")}
function live(d){let tasks;try{tasks=fs.readdirSync("/proc/"+d+"/task")}catch{return true}
if(tasks.length===0)return true;
for(const t of tasks){let st;
try{st=fs.readFileSync("/proc/"+d+"/task/"+t+"/stat","latin1")}catch{return true}
const s=st.slice(st.lastIndexOf(")")+2).split(" ")[0];if(s!=="Z"&&s!=="X")return true}
return false}
function ancestors(){const self=String(process.pid);const up=new Set([self]);
for(let p=self;;){let st;try{st=fs.readFileSync("/proc/"+p+"/stat","latin1")}catch{break}
const pp=st.slice(st.lastIndexOf(")")+2).split(" ")[1];if(!pp||pp==="0"||up.has(pp))break;up.add(pp);p=pp}
return up}
// clear kills every process that is not in keep, not an ancestor and not itself, until
// a scan finds none that could still be running, none it could not read, and every
// one it can see signalled. It returns null when it gave up, which is the caller's
// non-zero exit.
function clear(keep,up){const nap=()=>Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,20);
const hit=new Set();let rounds=0,killed=0;
for(;;){const doomed=[];let unresolved=0;
for(const d of fs.readdirSync("/proc")){if(!/^[0-9]+$/.test(d)||up.has(d))continue;
let st;try{st=fs.readFileSync("/proc/"+d+"/stat","latin1")}catch(e){if(!gone(e))unresolved++;continue}
const f=st.slice(st.lastIndexOf(")")+2).split(" ");if(kthread(f))continue;
let cmd;try{cmd=fs.readFileSync("/proc/"+d+"/cmdline").toString("hex")}catch(e){if(!gone(e))unresolved++;continue}
const id=d+":"+f[19];if(keep.has(id+":"+cmd))continue;
doomed.push([+d,id]);if(live(d)||!hit.has(id))unresolved++}
if(unresolved===0)return {rounds,killed};
if(++rounds>50)return null;
for(const [p,id] of doomed){try{process.kill(p,"SIGKILL");killed++;hit.add(id)}catch(e){if(gone(e))hit.add(id)}}
nap()}}
`

// ListScript lists every process except itself and its ancestors, and reads the
// host's Yama ptrace_scope, as JSON on stdout. Its output is trusted only where no
// call's code can have run: in a sandbox just created or just started, or right
// after a clean sweep when no interpreter is alive.
const ListScript = clearFn + `const fs=require("node:fs");const self=String(process.pid);const skip=new Set([self]);
for(let p=self;;){let st;try{st=fs.readFileSync("/proc/"+p+"/stat","latin1")}catch{break}
const pp=st.slice(st.lastIndexOf(")")+2).split(" ")[1];if(!pp||pp==="0"||skip.has(pp))break;skip.add(pp);p=pp}
const procs=[];for(const d of fs.readdirSync("/proc")){if(!/^[0-9]+$/.test(d)||(skip.has(d)&&d!=="1")||!live(d))continue;
try{const st=fs.readFileSync("/proc/"+d+"/stat","latin1");const f=st.slice(st.lastIndexOf(")")+2).split(" ");if(kthread(f))continue;
const raw=fs.readFileSync("/proc/"+d+"/cmdline","latin1");const cmd=raw.split("\0").join(" ").trim();
const um=/^Uid:\s+(\d+)/m.exec(fs.readFileSync("/proc/"+d+"/status","latin1"));
procs.push({pid:+d,ppid:+f[1],state:f[0],start:f[19],uid:um?+um[1]:-1,cmd,cmdHex:Buffer.from(raw,"latin1").toString("hex")})}catch{}}
let ptrace="";try{ptrace=fs.readFileSync("/proc/sys/kernel/yama/ptrace_scope","latin1").trim()}catch{}
process.stdout.write(JSON.stringify({ptrace,procs}))`

// QuiesceScript kills every process in the sandbox that is not plimsoll's own, until
// a scan finds none: the interpreters a session keeps included, since a process the
// session's code controls must not be running when plimsoll starts a process of its
// own. Arguments: the identities to leave alone (the sandbox's own processes and the
// relays, which are plimsoll's). Its exit status is the verdict (QuiesceClean); its
// stdout is a summary for the log only.
//
// Why killing and not stopping, which would keep a session's cell state: a stopped
// process can arrange its own resume before it is stopped, with no other process
// involved. SIGCONT takes effect when it is generated, and the kernel generates it for
// asynchronous file descriptor notifications (fcntl F_SETSIG), POSIX timers and message
// queues; a seccomp filter cannot tell those apart from the uses a language runtime
// makes of them, since the signal travels in a structure, not an argument. The
// round-4 review measured a stopped process going back to sleeping through F_SETSIG
// alone (2026-10-08). A killed process has no such recourse, and with every parent dead no new
// one appears.
//
// What the window is: until a program of plimsoll's has loaded the runner guard, a
// process of the same uid can open its stdin, stdout and memory, and a descriptor
// opened before PR_SET_DUMPABLE=0 stays usable afterwards, memory included. The project
// runner's plan arrives on that stdin and carries the key its report is authenticated
// with.
const QuiesceScript = clearFn + `const fs=require("node:fs");const keep=new Set(process.argv.slice(1));
const out=clear(keep,ancestors());
if(out===null)process.exit(1);
process.stdout.write(JSON.stringify(out))`

// SweepScript kills every process that is not kept, not an ancestor and not itself,
// until a scan finds none, then measures the session's directories, unless the budget
// is 0, which measures nothing. Arguments: the disk budget in bytes (0 = none), the
// entry bound, how to measure (Measure), the directories to measure (joined by
// commas), then the identities to keep (pid:starttime:cmdline-hex, so a process that
// lands on a kept PID in the same clock tick is kept only if its command line matches
// too). Its exit status is the verdict (the Sweep* constants); its stdout is a summary
// for the log only.
const SweepScript = clearFn + `const fs=require("node:fs");const [budget,maxEntries,measure,dirList,...keepList]=process.argv.slice(1);
const cleared=clear(new Set(keepList),ancestors());
if(cleared===null)process.exit(1);
const {rounds,killed}=cleared;
let bytes=0,entries=0;const dirs=dirList.split(",").filter(Boolean);
if(+budget>0&&measure==="statfs"){for(const d of dirs){let s;try{s=fs.statfsSync(d)}catch{process.exit(11)}
bytes+=(s.blocks-s.bfree)*s.bsize}if(bytes>+budget)process.exit(10)}
else if(+budget>0)while(dirs.length>0){const dir=dirs.pop();let names;
try{names=fs.readdirSync(dir)}catch{let st;try{st=fs.lstatSync(dir)}catch{process.exit(11)}if(!st.isDirectory())continue;
try{fs.chmodSync(dir,0o700);names=fs.readdirSync(dir)}catch{process.exit(11)}}
for(const n of names){const p=dir+"/"+n;let st;try{st=fs.lstatSync(p)}catch{continue}
if(++entries>+maxEntries)process.exit(10);bytes+=st.blocks*512;if(bytes>+budget)process.exit(10);
if(st.isDirectory())dirs.push(p)}}
process.stdout.write(JSON.stringify({rounds,killed,bytes,entries}))`

// CheckScript checks identities a launcher or a relay reported, each given as
// kind:pid:starttime:cmdline-hex, and exits 0 when every one holds and 1 otherwise,
// saying why on stderr (for a log; only the status counts):
//   - relay: the process is live with that start time and command line, and its
//     parent is 0 (docker exec gives its process no parent in the container, and
//     code in it cannot make one; the container's init has parent 0 too, which the
//     command line, checked against the relay's own on the host first, rules out);
//     relay@N: the same, with parent N (on E2B, envd, which starts every relay and
//     which the session's code cannot ask to start anything without its token);
//   - interp: the process is live with that start time and command line, and no
//     other live process has the same command line.
//
// A launcher and a relay print their identities on stdout, and on docker code of the
// session can write into a new process's stdout while it starts, so it could name a
// process of its own for the sweep to keep. The host first requires the reported
// command line to be the one plimsoll started (argvHex), so only a process running
// that very program can be named. The provider runs this check as a user
// the session's code is not, so nothing in the sandbox can write into the check or
// change how it exits.
const CheckScript = clearFn + `const fs=require("node:fs");const procs=[];
for(const d of fs.readdirSync("/proc")){if(!/^[0-9]+$/.test(d)||!live(d))continue;let st,cmd;
try{st=fs.readFileSync("/proc/"+d+"/stat","latin1");cmd=fs.readFileSync("/proc/"+d+"/cmdline").toString("hex")}catch{continue}
const f=st.slice(st.lastIndexOf(")")+2).split(" ");procs.push({pid:d,ppid:f[1],start:f[19],cmd})}
const why=[];if(process.argv.length<2)why.push("nothing to check");
for(const w of process.argv.slice(1)){const [kind,pid,start,cmd]=w.split(":");const p=procs.find(q=>q.pid===pid);
if(!p){why.push(pid+": no live process");continue}if(p.start!==start||p.cmd!==cmd){why.push(pid+": another start or command line");continue}
if(kind==="relay"||kind.startsWith("relay@")){const want=kind==="relay"?"0":kind.slice(6);if(p.ppid!==want)why.push(pid+": parent "+p.ppid)}
else if(kind==="interp"){const n=procs.filter(q=>q.cmd===cmd).length;if(n!==1)why.push(pid+": "+n+" processes with its command line")}
else why.push(pid+": unknown kind")}
if(why.length>0)process.stderr.write(why.join("; ")+"\n");process.exit(why.length>0?1:0)`

// CheckArgv is the check's command line for identities given as kind:identity.
func CheckArgv(ids []string) []string { return append([]string{"node", "-e", CheckScript}, ids...) }

// ListArgv is the lister's command line.
func ListArgv() []string { return []string{"node", "-e", ListScript} }

// Measure is how the sweep measures a session's files against its budget.
type Measure string

const (
	// MeasureStatfs reads the usage of each directory's filesystem: for directories
	// that are each a size-capped tmpfs of their own (docker's), everything on them,
	// a file deleted while a process holds it open included, and nothing the
	// session's code can steer.
	MeasureStatfs Measure = "statfs"
	// MeasureWalk walks the directories and sums what lstat reports, up to
	// MaxDiskEntries entries, for directories on a filesystem the session shares
	// (openshell's /tmp). Code of the session can hide files from it (one deleted
	// while a process holds it open, a directory swapped for a link mid-walk), so it
	// is an estimate of what the session keeps, not a bound.
	MeasureWalk Measure = "walk"
)

// SweepArgv is the sweep's command line: the disk budget (0 measures nothing), how
// to measure, the directories it measures, and every process identity to keep.
func SweepArgv(diskBytes int64, measure Measure, dirs []string, keep []string) []string {
	return append([]string{"node", "-e", SweepScript, strconv.FormatInt(diskBytes, 10),
		strconv.Itoa(MaxDiskEntries), string(measure), strings.Join(dirs, ",")}, keep...)
}

// QuiesceArgv is the quiesce's command line: the identities to leave alone, which are
// plimsoll's own processes (the sandbox's own and the relays). Everything else in the
// sandbox is killed, the session's interpreters included.
func QuiesceArgv(own []string) []string {
	return append([]string{"node", "-e", QuiesceScript}, own...)
}

// Process is one entry of the lister's output.
type Process struct {
	PID    int    `json:"pid"`
	PPID   int    `json:"ppid"`
	State  string `json:"state"`
	Start  string `json:"start"`
	UID    int    `json:"uid"` // the real uid, -1 when it could not be read
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

// BaselineAll reads the lister's output from a virtual machine no call has touched and
// returns the identities of all its processes, which every sweep keeps: a machine
// runs an init and system services, not docker's PID 1 and one main process. Nothing
// of the session's has run, so every process listed is the machine's own. It refuses a
// listing without PID 1, and one where a process runs as guest, the uid the session's
// code will run as: the guest could signal or attach to a process of its own uid, and
// a kept one would outlive every sweep.
func BaselineAll(stdout []byte, guest int) ([]string, error) {
	l, err := ParseListing(stdout)
	if err != nil {
		return nil, err
	}
	keep := make([]string, 0, len(l.Procs))
	init := false
	for _, pr := range l.Procs {
		if pr.UID == guest {
			return nil, fmt.Errorf("an untouched machine runs pid %d %q as uid %d, the uid the session's code runs as", pr.PID, pr.Cmd, guest)
		}
		if pr.UID < 0 {
			return nil, fmt.Errorf("an untouched machine runs pid %d %q, whose uid could not be read", pr.PID, pr.Cmd)
		}
		init = init || pr.PID == 1
		keep = append(keep, pr.Identity())
	}
	if !init {
		return nil, errors.New("the process list of an untouched machine has no PID 1")
	}
	return keep, nil
}
