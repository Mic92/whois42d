package whois

import (
	"flag"
	"strings"
)

func shellSplit(s string) []string {
	split := strings.Split(s, " ")

	var result []string
	var inquote string
	var block string
	for _, i := range split {
		if inquote == "" {
			if strings.HasPrefix(i, "'") || strings.HasPrefix(i, "\"") {
				inquote = string(i[0])
				block = strings.TrimPrefix(i, inquote) + " "
			} else {
				result = append(result, i)
			}
		} else {
			if !strings.HasSuffix(i, inquote) {
				block += i + " "
			} else {
				block += strings.TrimSuffix(i, inquote)
				inquote = ""
				result = append(result, block)
				block = ""
			}
		}
	}

	return result
}

type Flags struct {
	ServerInfo string
	TypeSchema string
	Types      map[string]bool
	Args       []string
}

func parseFlags(request string) (*Flags, *flag.FlagSet, error) {
	args := shellSplit(request)
	set := flag.NewFlagSet("whois42d", flag.ContinueOnError)
	var typeField string
	f := Flags{}
	set.StringVar(&f.ServerInfo, "q", "", "[version|sources|types] query specified server info")
	set.StringVar(&f.TypeSchema, "t", "", "request template for object of TYPE")
	set.StringVar(&typeField, "T", "", "TYPE[,TYPE]... only look for objects of TYPE")

	if err := set.Parse(args); err != nil {
		return nil, set, err
	}

	if typeField != "" {
		types := strings.Split(typeField, ",")
		f.Types = make(map[string]bool, len(types))
		for _, t := range types {
			f.Types[t] = true
		}
	}

	f.Args = set.Args()
	return &f, set, nil
}
