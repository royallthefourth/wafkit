package wafkit

type TrieNode struct {
	children map[rune]*TrieNode
	value    string
}

func (n *TrieNode) Contains(key string) bool {
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

func (n *TrieNode) Insert(key string) {
	current := n
	for _, r := range key {
		if current.children == nil {
			current.children = map[rune]*TrieNode{}
		}
		if child, ok := current.children[r]; ok {
			current = child
		} else {
			current.children[r] = &TrieNode{value: key}
		}
	}
}
