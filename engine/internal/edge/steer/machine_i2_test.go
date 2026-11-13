package steer

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"slices"
	"strings"
	"testing"
)

// i2Rule is I2 as the pin's failures quote it.
const i2Rule = `
I2: withdraw is reachable only from Triggers. Step's one way out of service is out, whose inputs
are a Triggers value, the drain's reason and the time; gates, the probe class and the report reach
the join path and nothing else, and Step's verdict is the automaton's own state, which enter alone
sets. Evaluate, the one-shot, answers StateDrain and StateWithdraw for the drain trigger, a hard
trigger and a running hold-down — which out alone arms — and for nothing else.`

// i2Exits is every place the package produces StateDrain or StateWithdraw:
// out's two calls of enter, and Evaluate's three answers, each under the one
// case that is its whole reason.
var i2Exits = []string{
	"Automaton.Evaluate [in.Triggers.Drained]: StateDrain",
	"Automaton.Evaluate [in.Triggers.Hard()]: StateWithdraw",
	"Automaton.Evaluate [now.Before(a.until)]: StateWithdraw",
	"Automaton.out: enter(StateDrain)",
	"Automaton.out: enter(StateWithdraw)",
}

var (
	// i2States are the State constants; a state is written by one of these
	// names or not at all.
	i2States = []string{"StateUnknown", "StateAnnounce", "StateWithdraw", "StateDrain"}
	// i2Named are the names a State field may be set to: a State constant,
	// or — Process.State shares the field name, and the pin reads names, not
	// types — a PIDState one.
	i2Named = append(slices.Clone(i2States), "PIDUnknown", "PIDAlive", "PIDGone")
)

// TestAutomatonOnlyOutTakesATargetOut pins I2's shape (Automaton's doc
// comment) over every non-test file of the package, read as syntax:
//
//   - StateDrain and StateWithdraw are produced — named anywhere but in a
//     comparison, a case list, a key or their own declaration — by out's two
//     calls of enter and by Evaluate's drain, hard and hold-down cases, and
//     nowhere else; and no State is computed (converted, added to, passed to
//     enter or stored in a State field from anything but a name), so a name
//     is the only way to make one;
//   - the automaton's state is written in enter alone, by plain assignment —
//     no ++, no &, no literal, no overwrite of the whole automaton; Step
//     returns the automaton's verdict, whose State is that field, and
//     nothing in the package answers with Evaluate in its place;
//   - out takes (Triggers, string, time.Time) and is called once, by Step,
//     with the tick's triggers and drain reason, which Step does not rewrite;
//     neither out nor enter nor sample is taken as a value;
//   - a hard sample enters the window from out alone; the window and the
//     tick that ages it are written by their own methods (and out's lift)
//     alone; the damping is never rewritten;
//   - a hold-down is armed by out alone — NewAutomaton restores a saved one —
//     for Evaluate answers withdraw while one runs.
//
// So Step's verdict is withdraw only when out entered it, and T3 checks that
// verdict against the automaton's state at every tick. This is a syntactic
// pin: a tripwire for the shapes a second way out of service would take, in
// any file of the package. T3 and its Evaluate arm prove the behaviour.
func TestAutomatonOnlyOutTakesATargetOut(t *testing.T) {
	p := &i2Pin{t: t, fset: token.NewFileSet()}
	for _, file := range p.parse() {
		for _, decl := range file.Decls {
			p.decl(decl)
		}
	}
	p.want("the places that produce StateDrain or StateWithdraw", p.exits, i2Exits)
	p.want("the calls of out", p.outs, []string{"Automaton.Step: a.out(in.Triggers, in.Drain.Reason, now)"})
	p.want("the hard samples entered", p.hard, []string{"Automaton.out"})
	p.want("the hold-downs armed", p.holds, []string{"Automaton.out"})
}

// i2Pin reads the package for TestAutomatonOnlyOutTakesATargetOut.
type i2Pin struct {
	t    *testing.T
	fset *token.FileSet

	// The declaration being read: its function ("Automaton.out",
	// "NewAutomaton"; "package-level" outside any), the receiver's name in a
	// method of Automaton, the name of a parameter of type Inputs; and the
	// path from the declaration down to the node being visited.
	fn, recv, in string
	stack        []ast.Node

	// What the whole package does, for the checks that need all of it.
	exits, outs, hard, holds []string
}

// parse reads every non-test file of the package, whatever its build tags,
// and fails when machine.go is not among them: the pin must not pass by
// reading nothing.
func (p *i2Pin) parse() []*ast.File {
	entries, err := os.ReadDir(".")
	if err != nil {
		p.t.Fatal(err)
	}
	var files []*ast.File
	machine := false
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(p.fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			p.t.Fatal(err)
		}
		files = append(files, f)
		machine = machine || name == "machine.go"
	}
	if !machine {
		p.t.Fatalf("read %d files, and machine.go is not among them: the pin is reading the wrong directory", len(files))
	}
	return files
}

// decl reads one top-level declaration: a function under its name, the
// receiver's type first — so Automaton.out is not another type's out — and
// anything else, a func literal in a var included, as package-level code.
func (p *i2Pin) decl(decl ast.Decl) {
	p.fn, p.recv, p.in = "package-level", "", ""
	if fn, ok := decl.(*ast.FuncDecl); ok {
		p.fn = fn.Name.Name
		if fn.Recv != nil && len(fn.Recv.List) == 1 {
			typ := fn.Recv.List[0].Type
			if star, ok := typ.(*ast.StarExpr); ok {
				typ = star.X
			}
			p.fn = types.ExprString(typ) + "." + p.fn
			if names := fn.Recv.List[0].Names; types.ExprString(typ) == "Automaton" && len(names) == 1 {
				p.recv = names[0].Name
			}
		}
		for _, field := range fn.Type.Params.List {
			if types.ExprString(field.Type) == "Inputs" && len(field.Names) == 1 {
				p.in = field.Names[0].Name
			}
		}
		if p.fn == "Automaton.out" {
			p.outTakes(fn)
		}
	}
	p.stack = p.stack[:0]
	ast.Inspect(decl, func(n ast.Node) bool {
		if n == nil {
			p.stack = p.stack[:len(p.stack)-1]
			return true
		}
		p.stack = append(p.stack, n)
		p.visit(n)
		return true
	})
}

func (p *i2Pin) visit(n ast.Node) {
	switch n := n.(type) {
	case *ast.Ident:
		p.produces(n)
	case *ast.SelectorExpr:
		p.methodValue(n)
	case *ast.CallExpr:
		p.call(n)
	case *ast.AssignStmt:
		for i, lhs := range n.Lhs {
			var value ast.Expr
			if len(n.Rhs) == len(n.Lhs) {
				value = n.Rhs[i]
			}
			p.write(n, lhs, value, n.Tok)
		}
	case *ast.IncDecStmt:
		p.write(n, n.X, nil, n.Tok)
	case *ast.UnaryExpr:
		if n.Op == token.AND { // an address taken is a write deferred
			p.write(n, n.X, nil, n.Op)
		}
	case *ast.RangeStmt:
		if n.Tok == token.ASSIGN {
			p.write(n, n.Key, nil, n.Tok)
			p.write(n, n.Value, nil, n.Tok)
		}
	case *ast.CompositeLit:
		p.literal(n)
	case *ast.BinaryExpr:
		p.arithmetic(n)
	case *ast.ReturnStmt:
		p.stepReturns(n)
	}
}

// outTakes pins out's inputs: a Triggers value, the drain's reason and the
// time — nothing a gate, the probe class or the report could steer.
func (p *i2Pin) outTakes(fn *ast.FuncDecl) {
	var params []string
	for _, f := range fn.Type.Params.List {
		for range max(len(f.Names), 1) {
			params = append(params, types.ExprString(f.Type))
		}
	}
	if want := []string{"Triggers", "string", "time.Time"}; !slices.Equal(params, want) {
		p.bad(fn, "takes (%s), want (%s)", strings.Join(params, ", "), strings.Join(want, ", "))
	}
}

// produces records a use of StateDrain or StateWithdraw that produces one —
// any use but an operand of a comparison, an entry of a case list, a key, or
// the constant's own declaration — under its function, and, in Evaluate,
// under the case it answers.
func (p *i2Pin) produces(id *ast.Ident) {
	if id.Name != "StateDrain" && id.Name != "StateWithdraw" {
		return
	}
	switch parent := p.parent().(type) {
	case *ast.BinaryExpr:
		switch parent.Op {
		case token.EQL, token.NEQ, token.LSS, token.GTR, token.LEQ, token.GEQ:
			return
		}
	case *ast.CaseClause:
		if slices.Contains(parent.List, ast.Expr(id)) {
			return
		}
	case *ast.KeyValueExpr:
		if parent.Key == ast.Expr(id) {
			return
		}
	case *ast.ValueSpec:
		if slices.Contains(parent.Names, id) {
			return
		}
	case *ast.CallExpr:
		if i2Calls(parent, "enter") && len(parent.Args) > 0 && parent.Args[0] == ast.Expr(id) {
			p.exits = append(p.exits, p.fn+": enter("+id.Name+")")
			return
		}
	}
	where := p.fn
	if p.fn == "Automaton.Evaluate" {
		where += " [" + p.caseOf() + "]"
	}
	p.exits = append(p.exits, where+": "+id.Name)
}

// caseOf names the innermost case the node sits under: its expressions, or
// "default", or "no case".
func (p *i2Pin) caseOf() string {
	for i := len(p.stack) - 1; i >= 0; i-- {
		cc, ok := p.stack[i].(*ast.CaseClause)
		if !ok {
			continue
		}
		if cc.List == nil {
			return "default"
		}
		var conds []string
		for _, e := range cc.List {
			conds = append(conds, types.ExprString(e))
		}
		return strings.Join(conds, ", ")
	}
	return "no case"
}

// methodValue fails enter, out or sample taken as a value: called through a
// variable, it acts where no name says so.
func (p *i2Pin) methodValue(sel *ast.SelectorExpr) {
	switch sel.Sel.Name {
	case "enter", "out", "sample":
	default:
		return
	}
	if call, ok := p.parent().(*ast.CallExpr); !ok || call.Fun != ast.Expr(sel) {
		p.bad(sel, "takes %s as a value; call it by name", types.ExprString(sel))
	}
}

func (p *i2Pin) call(call *ast.CallExpr) {
	switch {
	case i2Calls(call, "enter"):
		if len(call.Args) == 0 || !i2Is(call.Args[0], i2States...) {
			p.bad(call, "calls enter with a state that is not named (%s); name it", types.ExprString(call))
		}
	case i2Calls(call, "out"):
		p.outs = append(p.outs, p.fn+": "+types.ExprString(call))
	case i2Calls(call, "sample"):
		switch {
		case len(call.Args) == 1 && i2Is(call.Args[0], "true"):
			p.hard = append(p.hard, p.fn)
		case len(call.Args) == 1 && i2Is(call.Args[0], "false"):
		default:
			p.bad(call, "enters a sample whose kind is not spelled true or false (%s)", types.ExprString(call))
		}
	case i2Calls(call, "Evaluate"):
		p.bad(call, "answers with Evaluate, the one-shot for a caller without the daemon; in this package Step's verdict is the automaton's state")
	case i2Is(call.Fun, "State"):
		p.bad(call, "converts to a State (%s); name the state", types.ExprString(call))
	}
}

// write checks one write — an assignment, ++ or --, a range clause, or an
// address taken — against the fields I2 rests on. value is what a plain
// assignment stores, nil when there is none to read.
func (p *i2Pin) write(at ast.Node, target, value ast.Expr, tok token.Token) {
	if target == nil {
		return
	}
	target = ast.Unparen(target)
	text := types.ExprString(target)
	plain := (tok == token.ASSIGN || tok == token.DEFINE) && value != nil
	switch {
	case i2Touches(target, "state"):
		if p.fn != "Automaton.enter" || !plain || text != p.recv+".state" {
			p.bad(at, "writes the automaton's state (%s); enter alone sets it", text)
		}
	case i2Touches(target, "cfg"):
		p.bad(at, "rewrites the damping (%s), which decides when hard samples withdraw", text)
	case i2Touches(target, "tick"):
		if p.fn != "Automaton.Step" || tok != token.INC || text != p.recv+".tick" {
			p.bad(at, "moves the tick (%s), by which the window ages; Step alone counts it", text)
		}
	case i2Touches(target, "window"), i2Touches(target, "hard"):
		lift := p.fn == "Automaton.out" && plain && text == p.recv+".window" && types.ExprString(value) == p.recv+".window[:0]"
		if !lift && p.fn != "Automaton.sample" && p.fn != "Automaton.age" {
			p.bad(at, "writes the window (%s); sample enters a sample, age drops old ones, and out's lift clears it", text)
		}
	case i2Touches(target, "until"):
		switch {
		case !plain:
			p.bad(at, "moves the hold-down's end (%s) other than by setting it", text)
		case types.ExprString(value) != "time.Time{}":
			p.holds = append(p.holds, p.fn)
		}
	case i2Touches(target, "State"):
		if !plain || !p.named(value) {
			p.bad(at, "sets %s to a state that is not named; name it — a State or PIDState constant, or the automaton's state", text)
		}
	}
	if star, ok := target.(*ast.StarExpr); ok && p.recv != "" && i2Is(star.X, p.recv) {
		p.bad(at, "overwrites the whole automaton, its state with it")
	}
	if p.in != "" && i2Root(target) == p.in {
		p.bad(at, "rewrites the tick's inputs (%s); out must see the triggers as they came", text)
	}
}

// literal checks a composite literal: no key sets the automaton's state, or
// its damping, window, samples or hold-down outside the function that owns
// them; a State is named; and the types the pin reads are keyed.
func (p *i2Pin) literal(lit *ast.CompositeLit) {
	typ := ""
	if lit.Type != nil {
		typ = types.ExprString(lit.Type)
	}
	keyed := true
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			keyed = false
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "state":
			p.bad(kv, "sets the automaton's state in a literal; enter alone sets it, and NewAutomaton starts from its zero value, StateUnknown")
		case "cfg", "window":
			if p.fn != "NewAutomaton" {
				p.bad(kv, "sets the automaton's %s in a literal outside NewAutomaton", key.Name)
			}
		case "until":
			if p.fn != "NewAutomaton" || types.ExprString(kv.Value) != "saved.Until" {
				p.bad(kv, "arms a hold-down in a literal (%s); NewAutomaton restores the saved one, out arms the rest", types.ExprString(kv.Value))
			}
		case "tick", "hard":
			if p.fn != "Automaton.sample" {
				p.bad(kv, "builds a sample outside sample")
			}
		case "State":
			if typ != "Process" && !p.named(kv.Value) {
				p.bad(kv, "builds a verdict whose State is not named (%s); name it", types.ExprString(kv.Value))
			}
		}
	}
	if !keyed && slices.Contains([]string{"Automaton", "autoSample", "Verdict"}, typ) {
		p.bad(lit, "builds a %s without keys, which this pin cannot read; key it", typ)
	}
}

// arithmetic fails arithmetic on a State constant: it makes a state no name
// shows.
func (p *i2Pin) arithmetic(bin *ast.BinaryExpr) {
	switch bin.Op {
	case token.EQL, token.NEQ, token.LSS, token.GTR, token.LEQ, token.GEQ, token.LAND, token.LOR:
		return
	}
	if i2Is(bin.X, i2States...) || i2Is(bin.Y, i2States...) {
		p.bad(bin, "computes a State (%s); name the state", types.ExprString(bin))
	}
}

// stepReturns pins what Step answers: the automaton's verdict, whose State is
// its state, and nothing put in its place.
func (p *i2Pin) stepReturns(ret *ast.ReturnStmt) {
	if p.fn != "Automaton.Step" {
		return
	}
	for i := len(p.stack) - 2; i >= 0; i-- {
		if _, ok := p.stack[i].(*ast.FuncLit); ok {
			return // a func literal's return, not Step's
		}
	}
	if len(ret.Results) == 1 {
		if call, ok := ret.Results[0].(*ast.CallExpr); ok && i2Calls(call, "verdict") && i2Is(call.Fun.(*ast.SelectorExpr).X, p.recv) {
			return
		}
	}
	p.bad(ret, "returns something other than %s.verdict(…); Step's verdict is the automaton's own state", p.recv)
}

// named reports whether a State field may be set to e: a constant by name, or
// the automaton's own state.
func (p *i2Pin) named(e ast.Expr) bool {
	return e != nil && (i2Is(e, i2Named...) || p.recv != "" && types.ExprString(ast.Unparen(e)) == p.recv+".state")
}

func (p *i2Pin) parent() ast.Node {
	if len(p.stack) < 2 {
		return nil
	}
	return p.stack[len(p.stack)-2]
}

func (p *i2Pin) bad(n ast.Node, format string, args ...any) {
	p.t.Helper()
	p.t.Errorf("%s: %s %s%s", p.fset.Position(n.Pos()), p.fn, fmt.Sprintf(format, args...), i2Rule)
}

func (p *i2Pin) want(what string, got, want []string) {
	p.t.Helper()
	slices.Sort(got)
	if !slices.Equal(got, want) {
		p.t.Errorf("%s are\n\t%s\nwant exactly\n\t%s%s", what, strings.Join(got, "\n\t"), strings.Join(want, "\n\t"), i2Rule)
	}
}

// i2Calls reports whether call calls a method named name.
func i2Calls(call *ast.CallExpr, name string) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	return ok && sel.Sel.Name == name
}

// i2Is reports whether e is one of the identifiers names.
func i2Is(e ast.Expr, names ...string) bool {
	id, ok := ast.Unparen(e).(*ast.Ident)
	return ok && slices.Contains(names, id.Name)
}

// i2Touches reports whether e reaches a field named field: e itself, or what
// e indexes, slices or dereferences on the way down.
func i2Touches(e ast.Expr, field string) bool {
	for {
		switch x := ast.Unparen(e).(type) {
		case *ast.SelectorExpr:
			if x.Sel.Name == field {
				return true
			}
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.SliceExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		default:
			return false
		}
	}
}

// i2Root is the variable a written expression hangs from: in for
// in.Triggers.Refused.
func i2Root(e ast.Expr) string {
	for {
		switch x := ast.Unparen(e).(type) {
		case *ast.Ident:
			return x.Name
		case *ast.SelectorExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.SliceExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		default:
			return ""
		}
	}
}
