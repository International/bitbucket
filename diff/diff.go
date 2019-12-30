package diff

import (
	"github.com/International/diffparser"
	"io"
	"io/ioutil"
)


// +gen slice:"Any"
type LineNumber int

// LineNumberSlice is a slice of type LineNumber. Use it where you would use []LineNumber.
type LineNumberSlice []LineNumber

// Any verifies that one or more elements of LineNumberSlice return true for the passed func. See: http://clipperhouse.github.io/gen/#Any
func (rcv LineNumberSlice) Any(fn func(LineNumber) bool) bool {
	for _, v := range rcv {
		if fn(v) {
			return true
		}
	}
	return false
}

// +gen slice:"First"
type ModifiedFile struct {
	OldName string
	CurrentName string
	LineNumbers LineNumberSlice
}

func ReadDiff(reader io.Reader) ([]ModifiedFile,error) {
	contents, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read diff contents")
	}
	diff, err := diffparser.Parse(string(contents))
	if err != nil {
		return nil, errors.Wrap(err, "could not parse diff")
	}
	modifiedFiles := make([]ModifiedFile, 0, len(diff.Files))
	for _, file := range diff.Files {
		changedFile := ModifiedFile{CurrentName: file.NewName, OldName: file.OrigName}

		for _, hunk := range file.Hunks {
			for _, line := range hunk.NewRange.Lines {
				if line.Mode == diffparser.UNCHANGED {
					continue
				}
				changedFile.LineNumbers = append(changedFile.LineNumbers, LineNumber(line.Number))
			}
		}

		modifiedFiles = append(modifiedFiles, changedFile)
	}

	return modifiedFiles, nil
}

