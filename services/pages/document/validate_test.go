package document

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClosedTiptapVocabularyAndLimits(t *testing.T) {
	good := `{"type":"doc","content":[{"type":"heading","attrs":{"level":2},"content":[{"type":"text","text":"Title"}]},{"type":"paragraph","content":[{"type":"text","text":"safe","marks":[{"type":"link","attrs":{"href":"https://example.test"}}]}]},{"type":"taskList","content":[{"type":"taskItem","attrs":{"checked":false},"content":[{"type":"paragraph"}]}]},{"type":"table","content":[{"type":"tableRow","content":[{"type":"tableCell","attrs":{"colspan":1,"rowspan":1,"colwidth":null},"content":[{"type":"paragraph"}]}]}]},{"type":"codeBlock","attrs":{"language":"go"},"content":[{"type":"text","text":"fmt.Println()"}]}]}`
	if _, err := Validate(json.RawMessage(good)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{"type":"doc","content":[{"type":"html","text":"<script>evil()</script>"}]}`,
		`{"type":"doc","content":[{"type":"paragraph","attrs":{"onclick":"evil()"}}]}`,
		`{"type":"doc","content":[{"type":"image","attrs":{"src":"https://evil.test"}}]}`,
		strings.Replace(good, "https://example.test", "javascript:alert(1)", 1),
		strings.Replace(good, `"language":"go"`, `"language":"<script>"`, 1),
		strings.Replace(good, `"level":2`, `"level":99`, 1),
		strings.Replace(good, `"colspan":1`, `"colspan":9999`, 1),
		good + ` {"type":"doc"}`,
	} {
		if _, err := Validate(json.RawMessage(raw)); err == nil {
			t.Fatalf("unsafe/invalid document accepted: %s", raw)
		}
	}
	deep := `{"type":"paragraph"}`
	for i := 0; i < 33; i++ {
		deep = `{"type":"blockquote","content":[` + deep + `]}`
	}
	if _, err := Validate(json.RawMessage(`{"type":"doc","content":[` + deep + `]}`)); err == nil {
		t.Fatal("excess depth accepted")
	}
	many := `{"type":"doc","content":[` + strings.TrimSuffix(strings.Repeat(`{"type":"paragraph"},`, 2001), ",") + `]}`
	if _, err := Validate(json.RawMessage(many)); err == nil {
		t.Fatal("excess nodes accepted")
	}
	huge := `{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"` + strings.Repeat("<", 12000) + `"}]}]}`
	if _, err := Validate(json.RawMessage(huge)); err == nil {
		t.Fatal("escaped JSON size limit bypassed")
	}
}
