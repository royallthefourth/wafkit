package wafkit

import "testing"

func TestTrieNode(t *testing.T) {
	present := []string{`dog`, `daffodil`}
	notPresent := []string{`do`, `asdf`}

	trie := trieNode{}
	for _, word := range present {
		trie.Insert(word)
	}

	for _, word := range notPresent {
		if trie.Contains(word) {
			t.Errorf(`trie should not contain %s`, word)
		}
	}

	for _, word := range present {
		if !trie.Contains(word) {
			t.Errorf(`trie should contain %s`, word)
		}
	}
}
