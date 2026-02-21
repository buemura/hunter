package dirs

import (
	"bufio"
	_ "embed"
	"os"
	"strings"
)

//go:embed wordlist.txt
var defaultWordlist string

// LoadWordlist loads paths from the given file. If path is empty, it falls
// back to the embedded default wordlist.
func LoadWordlist(path string) ([]string, error) {
	if path == "" {
		return parseLines(defaultWordlist), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return parseLines(string(data)), nil
}

// parseLines splits text into non-empty, trimmed lines, skipping comments.
func parseLines(text string) []string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}
