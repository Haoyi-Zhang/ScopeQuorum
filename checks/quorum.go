// Independent finite audit of cardinality quorums. No protocol imports.
// Enumerates all quorum masks for every 1<=n<=10, 0<=f<n, 1<=q<=n.
package main

import (
	"encoding/json"
	"fmt"
	"math/bits"
	"os"
)

type Row struct {
	N                    int  `json:"n"`
	F                    int  `json:"f"`
	Q                    int  `json:"q"`
	MinIntersection      int  `json:"min_intersection"`
	Safe                 bool `json:"safe"`
	CanFormWithoutFaulty bool `json:"threshold_available"`
}

func main() {
	rows := []Row{}
	failed := 0
	pairChecks := 0
	for n := 1; n <= 10; n++ {
		for q := 1; q <= n; q++ {
			quorums := []uint{}
			for m := uint(0); m < (1 << n); m++ {
				if bits.OnesCount(m) == q {
					quorums = append(quorums, m)
				}
			}
			min := n
			for _, a := range quorums {
				for _, b := range quorums {
					pairChecks++
					v := bits.OnesCount(a & b)
					if v < min {
						min = v
					}
				}
			}
			for f := 0; f < n; f++ {
				safe := min > f
				available := false
				honestMask := uint((1 << (n - f)) - 1)
				for _, a := range quorums {
					if a & ^honestMask == 0 {
						available = true
						break
					}
				}
				if safe != (2*q-n > f) || available != (q <= n-f) {
					failed++
				}
				rows = append(rows, Row{n, f, q, min, safe, available})
			}
		}
	}
	existence := 0
	for n := 1; n <= 10; n++ {
		for f := 0; f < n; f++ {
			exists := false
			for _, r := range rows {
				if r.N == n && r.F == f && r.Safe && r.CanFormWithoutFaulty {
					exists = true
				}
			}
			if exists != (n > 3*f) {
				failed++
			}
			existence++
		}
	}
	out := map[string]interface{}{"model": "cardinality quorums; at most f Byzantine identities; no protocol liveness claim", "parameter_rows": len(rows), "quorum_pair_checks": pairChecks, "existence_checks": existence, "failures": failed, "rows": rows}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if failed != 0 {
		os.Exit(1)
	}
}
