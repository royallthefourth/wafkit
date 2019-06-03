package wafkit

type trieNode struct {
	children map[rune]*trieNode
	value    string
}

func (n *trieNode) Contains(key string) bool {
	current := n
	for _, r := range key {
		if current.value == key {
			return true
		} else if child, ok := current.children[r]; ok {
			current = child
		} else {
			break
		}
	}
	return false
}

func (n *trieNode) Insert(key string) {
	current := n
	for _, r := range key {
		if current.children == nil {
			current.children = map[rune]*trieNode{}
		}
		if child, ok := current.children[r]; ok {
			current = child
		} else {
			current.children[r] = &trieNode{value: key}
		}
	}
}
