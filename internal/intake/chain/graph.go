package chain

// Graph indexes transitions and chains for existence queries and synthesis.
type Graph struct {
	out    map[string][]Transition // keyed by PRE-capability id
	txByID map[string]Transition

	chains      map[string]Chain
	prefixes    map[string]bool
	txToChains  map[string]map[string]bool
	byEndpoints map[string][]string // "start|end" cap ids -> chain_ids
	chainBloom  map[string]*bloom
}

func NewGraph() *Graph {
	return &Graph{
		out:         map[string][]Transition{},
		txByID:      map[string]Transition{},
		chains:      map[string]Chain{},
		prefixes:    map[string]bool{},
		txToChains:  map[string]map[string]bool{},
		byEndpoints: map[string][]string{},
		chainBloom:  map[string]*bloom{},
	}
}

func (g *Graph) AddTransition(t Transition) {
	id := t.ID()
	if _, ok := g.txByID[id]; ok {
		return
	}
	g.txByID[id] = t
	pre := t.Pre.ID()
	g.out[pre] = append(g.out[pre], t)
}

func (g *Graph) AddChain(c Chain) {
	if !c.Valid() {
		return
	}
	for _, t := range c.Transitions {
		g.AddTransition(t)
	}
	cid := c.ID()
	g.chains[cid] = c
	for _, p := range c.PrefixIDs() {
		g.prefixes[p] = true
	}
	bl := newBloom(len(c.Transitions))
	for _, tid := range c.TransitionIDs() {
		if g.txToChains[tid] == nil {
			g.txToChains[tid] = map[string]bool{}
		}
		g.txToChains[tid][cid] = true
		bl.add(tid)
	}
	g.chainBloom[cid] = bl
	ep := c.Start().ID() + "|" + c.End().ID()
	g.byEndpoints[ep] = append(g.byEndpoints[ep], cid)
}

func (g *Graph) HasChain(c Chain) bool { _, ok := g.chains[c.ID()]; return ok }

// HasPrefix reports whether some known chain starts with the given prefix chain.
func (g *Graph) HasPrefix(prefix Chain) bool {
	ids := prefix.PrefixIDs()
	if len(ids) == 0 {
		return false
	}
	return g.prefixes[ids[len(ids)-1]]
}

// ChainsContaining returns chain_ids containing t; the inverted index is authoritative (bloom is a negative pre-check).
func (g *Graph) ChainsContaining(t Transition) []string {
	tid := t.ID()
	var out []string
	for cid := range g.txToChains[tid] {
		if bl := g.chainBloom[cid]; bl == nil || bl.maybe(tid) {
			out = append(out, cid)
		}
	}
	return out
}

func (g *Graph) ChainsBetween(start, end Capability) []string {
	return g.byEndpoints[start.ID()+"|"+end.ID()]
}

// Synthesize BFS-searches a shortest path start→goal; the result is a plan to verify, never a proven exploit.
func (g *Graph) Synthesize(start, goal Capability) (Chain, bool) {
	startID, goalID := start.ID(), goal.ID()
	if startID == goalID {
		return Chain{}, false
	}
	type node struct {
		cap  string
		path []Transition
	}
	visited := map[string]bool{startID: true}
	queue := []node{{cap: startID}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, t := range g.out[cur.cap] {
			postID := t.Post.ID()
			if visited[postID] {
				continue
			}
			path := append(append([]Transition{}, cur.path...), t)
			if postID == goalID {
				return Chain{Transitions: path}, true
			}
			visited[postID] = true
			queue = append(queue, node{cap: postID, path: path})
		}
	}
	return Chain{}, false
}

type bloom struct {
	bits []uint64
	k    int
	m    uint64 // bit count
}

func newBloom(n int) *bloom {
	if n < 1 {
		n = 1
	}
	m := uint64(n * 16) // ~16 bits/element
	if m < 64 {
		m = 64
	}
	return &bloom{bits: make([]uint64, (m+63)/64), k: 4, m: m}
}

// two FNV-1a hashes; the k probes are h1 + i*h2
func (b *bloom) hashes(s string) [2]uint64 {
	var h1, h2 uint64 = 1469598103934665603, 1099511628211
	for i := 0; i < len(s); i++ {
		h1 = (h1 ^ uint64(s[i])) * 1099511628211
		h2 = (h2 ^ uint64(s[i])) * 1469598103934665603
	}
	return [2]uint64{h1, h2}
}

func (b *bloom) add(s string) {
	h := b.hashes(s)
	for i := 0; i < b.k; i++ {
		pos := (h[0] + uint64(i)*h[1]) % b.m
		b.bits[pos/64] |= 1 << (pos % 64)
	}
}

func (b *bloom) maybe(s string) bool {
	h := b.hashes(s)
	for i := 0; i < b.k; i++ {
		pos := (h[0] + uint64(i)*h[1]) % b.m
		if b.bits[pos/64]&(1<<(pos%64)) == 0 {
			return false
		}
	}
	return true
}
