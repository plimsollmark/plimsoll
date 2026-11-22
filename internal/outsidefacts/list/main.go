// Command list prints what the outside-facts check sees: every site the scan finds in product
// code with the row that answers it, every fixed wait in a test that carries no reason, and
// for each site with no row a row to copy into internal/outsidefacts/facts.json.
//
//	go run ./internal/outsidefacts/list            # only what is missing
//	go run ./internal/outsidefacts/list -all       # every site
//
// Run it from the repository's top directory. It exits 1 when something is missing.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/plimsollmark/plimsoll/internal/outsidefacts"
)

func main() {
	all := flag.Bool("all", false, "print every site, not only those with no row")
	root := flag.String("root", ".", "the repository's top directory")
	flag.Parse()

	table, err := outsidefacts.Load(filepath.Join(*root, "internal", "outsidefacts"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "list:", err)
		os.Exit(2)
	}
	sites, err := outsidefacts.Scan(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "list:", err)
		os.Exit(2)
	}
	waits, err := outsidefacts.ScanTests(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "list:", err)
		os.Exit(2)
	}
	missing := 0
	told := map[string]bool{}
	for _, s := range append(sites, waits...) {
		covered := table.Covers(s)
		if covered && !*all {
			continue
		}
		state := "row"
		if !covered {
			state = "NO ROW"
			missing++
		}
		fmt.Printf("%s\t%s:%d\t%s\t%s\t%s\n", state, s.File, s.Line, s.Symbol, s.Shape, s.Text)
		if !covered && !told[s.Key()] {
			told[s.Key()] = true
			if s.Shape == outsidefacts.ShapeFixedWait {
				fmt.Printf("    add a comment on the line above: // %s <why this wait is safe>\n", outsidefacts.WaitMarker)
			} else {
				fmt.Println(outsidefacts.Skeleton(s))
			}
		}
	}
	problems := append(table.Validate(), table.Current(*root)...)
	problems = append(problems, table.Unanswering(append(sites, waits...))...)
	for _, err := range problems {
		fmt.Println("TABLE\t" + err.Error())
	}
	missing += len(problems)
	fmt.Fprintf(os.Stderr, "%d sites in product code, %d unmarked fixed waits in tests, %d with no row or marker, or wrong in the table\n", len(sites), len(waits), missing)
	if missing > 0 {
		os.Exit(1)
	}
}
