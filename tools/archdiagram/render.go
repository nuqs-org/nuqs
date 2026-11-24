// Turns what we read into the architecture page: diagram, table and file tree.

package main

import (
	"fmt"
	"html"
	"slices"
	"strings"
)

// outFile is where the page is written, relative to the repo root.
const outFile = "docs/architecture.md"

// collapse lists folders whose sub-packages are drawn as one box, so the
// diagram stays readable when we have 50 checks instead of 3.
var collapse = []string{"checks"}

// folderNotes describes folders that have no Go code of their own.
// Folders with Go code use their package doc comment instead.
var folderNotes = map[string]string{
	"cmd":               "Programs you can run. Each folder here is one binary.",
	"internal":          "The core of Nuqs. Only code in this repo can import these.",
	"tools":             "Helper programs for developing Nuqs. Not part of the scanner.",
	"scripts":           "Small helper scripts used by CI.",
	".github":           "GitHub settings.",
	".github/workflows": "CI jobs. They run on every push and pull request.",
}

// node returns the diagram box a package belongs to.
func node(dir string) string {
	for _, c := range collapse {
		if strings.HasPrefix(dir, c+"/") {
			return c + "/*"
		}
	}
	return dir
}

func nodeID(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return "n_" + b.String()
}

func topFolder(dir string) string {
	top, _, _ := strings.Cut(dir, "/")
	return top
}

// Render builds the whole architecture page.
func Render(r *Repo) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	w("# Architecture\n\n")
	w("!!! note \"This page is generated\"\n")
	w("    `tools/archdiagram` builds it from the code on every push, so it always matches what's in the repo. Don't edit it by hand. Every description comes from the file itself: the package doc comment for folders, and the one-line comment at the top of each file.\n\n")

	w("## How the packages connect\n\n")
	w("Read it top-down. Each row is a layer, and an arrow means the row uses the rows below it. A package only uses packages in its own row or the rows below, never above. The docs build checks this, so the picture stays true. ")
	w("Blue is `cmd/`, grey is `internal/`, orange is `checks/`.\n\n")
	renderDiagram(&b, r, layers)
	w("\nThe table below says exactly which package uses which. The developer tools in `tools/` and `lab/`")
	if hasTestOnly(r) {
		w(", and test-only packages,")
	}
	w(" aren't drawn.\n")
	w("\n## Packages\n\n")
	w("| Package | What it does | Uses |\n|---|---|---|\n")
	for _, p := range r.Packages {
		uses := "nothing else in Nuqs"
		if len(p.Imports) > 0 {
			uses = "`" + strings.Join(p.Imports, "`, `") + "`"
		}
		name := "`" + p.Dir + "`"
		if p.TestOnly {
			name += " (tests)"
		}
		w("| %s | %s | %s |\n", name, orDash(p.Summary), uses)
	}

	w("\n## What's where\n\n")
	w("Every file in the repo, as git sees it, except the `docs/` and `test/` folders. Click a folder to open or close it.\n\n")
	w("%s", tree(r))
	return b.String()
}

// diagramSkip are top folders left out of the diagram. They're for
// developing Nuqs, not part of the program, and the table still lists them.
var diagramSkip = []string{"tools", "lab"}

// Layer is one row of the diagram.
type Layer struct {
	Name string
	Dirs []string // package folders, "cmd/*" means every folder inside cmd
}

// layers are the rows of the diagram, top to bottom. A package may only use
// packages in its own layer or below it, never above. Every package must be
// in a layer, so a new package means adding it here. The tool fails, and so
// does the test on the real repo, when a package is missing or uses a layer
// above it.
var layers = []Layer{
	{"Programs", []string{"cmd/*"}},
	{"Interfaces", []string{"internal/cli", "internal/web", "internal/api", "internal/output"}},
	{"Services", []string{"internal/tools", "internal/auth"}},
	{"Scanning", []string{"internal/diff", "internal/engine", "internal/nmap", "internal/progress", "internal/store", "internal/target"}},
	{"Checks", []string{"checks", "checks/*", "internal/sshprobe"}},
	{"Foundation", []string{"internal/model", "internal/check", "internal/version"}},
}

// classes colour the boxes by top folder.
var classes = []struct{ folder, style string }{
	{"cmd", "fill:#e3ecfa,stroke:#4a6fa5,color:#1d1d1f"},
	{"internal", "fill:#f4f4f5,stroke:#8a8a8e,color:#1d1d1f"},
	{"checks", "fill:#fbeedd,stroke:#c27c2c,color:#1d1d1f"},
}

// layerOf returns the index of the layer a package belongs to, or -1.
func layerOf(dir string, ls []Layer) int {
	for i, l := range ls {
		for _, d := range l.Dirs {
			if d == dir || (strings.HasSuffix(d, "/*") && strings.HasPrefix(dir, strings.TrimSuffix(d, "*"))) {
				return i
			}
		}
	}
	return -1
}

// drawn reports whether a package belongs in the diagram.
func drawn(p Package) bool {
	return !p.TestOnly && !slices.Contains(diagramSkip, topFolder(p.Dir))
}

// LayerProblems lists packages that aren't in a layer, or that use a
// package in a layer above them.
func LayerProblems(r *Repo, ls []Layer) []string {
	var out []string
	for _, p := range r.Packages {
		if !drawn(p) {
			continue
		}
		at := layerOf(p.Dir, ls)
		if at < 0 {
			out = append(out, fmt.Sprintf("%s isn't in a layer, add it to layers in tools/archdiagram/render.go", p.Dir))
			continue
		}
		for _, imp := range p.Imports {
			if to := layerOf(imp, ls); to >= 0 && to < at {
				out = append(out, fmt.Sprintf("%s (%s) uses %s (%s), a layer can only use its own layer or the ones below", p.Dir, ls[at].Name, imp, ls[to].Name))
			}
		}
	}
	return out
}

// renderDiagram draws the layers as rows, top to bottom, with one arrow
// from each row to the next. Arrows between single packages would cross
// more and more as Nuqs grows, rows don't: a new package is one more box in
// its row. Who uses whom exactly is in the table below the diagram.
func renderDiagram(b *strings.Builder, r *Repo, ls []Layer) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }

	members := map[string][]string{}
	rows := make([][]string, len(ls))
	for _, p := range r.Packages {
		at := layerOf(p.Dir, ls)
		if !drawn(p) || at < 0 {
			continue
		}
		n := node(p.Dir)
		if members[n] == nil {
			rows[at] = append(rows[at], n)
		}
		members[n] = append(members[n], strings.TrimPrefix(p.Dir, strings.TrimSuffix(n, "*")))
	}

	w("```mermaid\nflowchart TB\n")
	var shown []int
	for i, row := range rows {
		if len(row) == 0 {
			continue
		}
		shown = append(shown, i)
		slices.Sort(row)
		w("  subgraph %s [\"%s\"]\n", layerID(i), ls[i].Name)
		for _, n := range row {
			w("    %s[\"%s\"]\n", nodeID(n), boxLabel(n, members[n]))
		}
		w("  end\n")
	}
	// An invisible link from each row's first box to the next row's first
	// box keeps the rows in order, so every row stays one line of boxes.
	// Then one arrow goes from each row to the row below.
	for i := 1; i < len(shown); i++ {
		w("  %s ~~~ %s\n", nodeID(rows[shown[i-1]][0]), nodeID(rows[shown[i]][0]))
	}
	for i := 1; i < len(shown); i++ {
		w("  %s --> %s\n", layerID(shown[i-1]), layerID(shown[i]))
	}
	for _, i := range shown {
		w("  style %s %s\n", layerID(i), layerStyle)
	}
	for _, c := range classes {
		var in []string
		for _, row := range rows {
			for _, n := range row {
				if topFolder(n) == c.folder {
					in = append(in, nodeID(n))
				}
			}
		}
		if len(in) > 0 {
			slices.Sort(in)
			w("  classDef %s %s\n  class %s %s\n", c.folder, c.style, strings.Join(in, ","), c.folder)
		}
	}
	w("```\n")
}

// layerStyle is the light frame around each row.
const layerStyle = "fill:#fafafa,stroke:#d2d2d7,color:#6e6e73"

func layerID(i int) string { return fmt.Sprintf("layer%d", i) }

// boxLabel is the short name in bold with the full path under it.
func boxLabel(n string, members []string) string {
	name := n[strings.LastIndex(n, "/")+1:]
	switch {
	case strings.HasSuffix(n, "/*"):
		slices.Sort(members)
		return fmt.Sprintf("<b>%s</b><br/><small>%s</small>", n, strings.Join(members, ", "))
	case name == n: // a top-level package like checks, the path would only repeat it
		return "<b>" + n + "</b>"
	}
	return fmt.Sprintf("<b>%s</b><br/><small>%s</small>", name, n)
}

func hasTestOnly(r *Repo) bool {
	return slices.ContainsFunc(r.Packages, func(p Package) bool { return p.TestOnly })
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return strings.ReplaceAll(s, "|", "\\|")
}

// tree draws the folders and files as a tree that opens and closes, with
// a short note after each folder and file that has one.
func tree(r *Repo) string {
	notes := map[string]string{}
	for k, v := range folderNotes {
		notes[k] = v
	}
	for _, p := range r.Packages {
		if p.Summary != "" {
			notes[p.Dir] = p.Summary
		}
	}
	// testdata folders are shown as one line, they're only test fixtures.
	fixtures := map[string]int{}
	var files []string
	for _, f := range r.Files {
		if d, ok := testdataDir(f); ok {
			if fixtures[d] == 0 {
				files = append(files, d+"/") // a trailing slash marks a collapsed folder
			}
			fixtures[d]++
			continue
		}
		files = append(files, f)
	}
	for d, n := range fixtures {
		notes[d] = fmt.Sprintf("Sample files used by the tests next to it (%d %s).", n, plural(n, "file", "files"))
	}

	// Build a nested structure from the flat file list.
	type dir struct {
		dirs  map[string]*dir
		files []string
	}
	newDir := func() *dir { return &dir{dirs: map[string]*dir{}} }
	root := newDir()
	for _, f := range files {
		collapsed := strings.HasSuffix(f, "/")
		f = strings.TrimSuffix(f, "/")
		parts := strings.Split(f, "/")
		d := root
		for _, part := range parts[:len(parts)-1] {
			if d.dirs[part] == nil {
				d.dirs[part] = newDir()
			}
			d = d.dirs[part]
		}
		if collapsed {
			if d.dirs[parts[len(parts)-1]] == nil {
				d.dirs[parts[len(parts)-1]] = newDir()
			}
			continue
		}
		d.files = append(d.files, parts[len(parts)-1])
	}

	// Draw it as nested lists, each folder is a <details> the reader can
	// open and close. Raw HTML must have no blank lines, or Markdown breaks it.
	var b strings.Builder
	var walk func(d *dir, path string)
	walk = func(d *dir, path string) {
		var names []string
		for n := range d.dirs {
			names = append(names, n)
		}
		slices.Sort(names)
		b.WriteString("<ul>\n")
		for _, n := range names {
			full := strings.TrimPrefix(path+"/"+n, "/")
			label := "<code>" + html.EscapeString(n) + "/</code>" + noteHTML(notes[full])
			sub := d.dirs[n]
			if len(sub.dirs) == 0 && len(sub.files) == 0 { // a collapsed testdata folder
				b.WriteString(`<li class="folder">` + label + "</li>\n")
				continue
			}
			b.WriteString("<li><details><summary>" + label + "</summary>\n")
			walk(sub, full)
			b.WriteString("</details></li>\n")
		}
		for _, f := range d.files {
			note := r.Notes[strings.TrimPrefix(path+"/"+f, "/")]
			if note == notes[path] {
				note = "" // it only repeats the folder's note (one-file packages)
			}
			b.WriteString("<li><code>" + html.EscapeString(f) + "</code>" + noteHTML(note) + "</li>\n")
		}
		b.WriteString("</ul>\n")
	}
	b.WriteString(`<div class="file-tree">` + "\n")
	walk(root, "")
	b.WriteString("</div>\n")
	return b.String()
}

// noteHTML turns a note into a grey span, with `code` kept as code.
func noteHTML(note string) string {
	if note == "" {
		return ""
	}
	parts := strings.Split(html.EscapeString(note), "`")
	for i := 1; i < len(parts); i += 2 {
		parts[i] = "<code>" + parts[i] + "</code>"
	}
	return ` <span class="note">` + strings.Join(parts, "") + "</span>"
}

// testdataDir returns the outermost testdata folder a file is in.
func testdataDir(f string) (string, bool) {
	parts := strings.Split(f, "/")
	for i, p := range parts[:len(parts)-1] {
		if p == "testdata" {
			return strings.Join(parts[:i+1], "/"), true
		}
	}
	return "", false
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
