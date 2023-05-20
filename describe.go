package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/gobwas/glob"
	"github.com/shurcool/githubv4"
)

const description = `Like git-describe, but for GitHub repositories. See https://github.com/WillAbides/gh-describe for more details.`

var kongVars = kong.Vars{
	"commitish_help":     `commit-ish object names to describe.`,
	"contains_help":      `find the tag that comes after the commit`,
	"debug_help":         `debug search strategy on stderr`,
	"all_help":           `use any ref`,
	"tags_help":          `use any tag, even unannotated`,
	"long_help":          `always use long format`,
	"abbrev_help":        `use <n> digits to display object names`,
	"exact_match_help":   `only output exact matches`,
	"match_help":         `only consider tags matching <pattern>`,
	"exclude_help":       `do not consider tags matching <pattern>`,
	"always_help":        `show abbreviated commit object as fallback`,
	"regex_match_help":   `only consider tags matching <regex> (uses re2/go syntax)`,
	"regex_exclude_help": `do not consider tags matching <regex> (uses re2/go syntax)`,
	"repo_help":          `select another repository using the [HOST/]OWNER/REPO format`,
}

type cmd struct {
	Repo         string   `kong:"short=R,help=${repo_help}"`
	Commitish    []string `kong:"arg,name=commit-ish,default=HEAD,help=${commitish_help}"`
	Contains     bool     `kong:"help=${contains_help}"`
	Debug        bool     `kong:"help=${debug_help}"`
	All          bool     `kong:"help=${all_help}"`
	Tags         bool     `kong:"help=${tags_help}"`
	Long         bool     `kong:"help=${long_help}"`
	Abbrev       *int     `kong:"placeholder='<n>',help=${abbrev_help}"`
	ExactMatch   bool     `kong:"help=${exact_match_help}"`
	Match        []string `kong:"placeholder=<pattern>,help=${match_help}"`
	RegexMatch   []string `kong:"name=regex-match,placeholder=<regex>,help=${regex_match_help}"`
	Exclude      []string `kong:"placeholder=<pattern>,help=${exclude_help}"`
	RegexExclude []string `kong:"name=regex-exclude,placeholder=<regex>,help=${regex_exclude_help}"`
	Always       bool     `kong:"help=${always_help}"`

	// Unsupported options from git-describe.
	// Here so we can output a friendlier error message.
	FirstParent bool `kong:"first-parent,hidden"`
	NoMatch     bool `kong:"no-match,hidden"`
	NoExclude   bool `kong:"no-exclude,hidden"`
	Dirty       bool `kong:"dirty,hidden"`
	Broken      bool `kong:"broken,hidden"`
	Candidates  int  `kong:"candidates,hidden"`

	repository     repository.Repository
	graphqlClient  *api.GraphQLClient
	matchers       []glob.Glob
	excluders      []glob.Glob
	stdout         io.Writer
	stderr         io.Writer
	regexMatchers  []*regexp.Regexp
	regexExcluders []*regexp.Regexp
}

func fatalf(format string, args ...interface{}) error {
	return &fatalError{message: fmt.Sprintf(format, args...)}
}

func fatalErr(err error) error {
	return &fatalError{message: err.Error()}
}

type fatalError struct {
	message string
}

func (f *fatalError) Error() string {
	return fmt.Sprintf("fatal: %s", f.message)
}

func main() {
	var cli cmd
	parser := kong.Parse(&cli, kongVars, kong.Name("gh-describe"), kong.Description(description))
	_, err := parser.Parse(os.Args[1:])
	parser.FatalIfErrorf(err)
	ctx := context.Background()
	cli.stdout = os.Stdout
	cli.stderr = os.Stderr
	err = run(ctx, &cli)
	if err == nil {
		return
	}
	if _, ok := err.(*fatalError); ok {
		fmt.Fprintf(cli.stderr, "%s\n", err)
		os.Exit(128)
	} else {
		fmt.Fprintf(cli.stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cli *cmd) error {
	if cli == nil {
		cli = &cmd{}
	}

	// Permanently unsupported options.
	if cli.FirstParent {
		return fmt.Errorf("--first-parent is not supported because it is not available using the GitHub API")
	}
	if cli.Dirty {
		return fmt.Errorf("--dirty is not supported because it is not relevant when using the GitHub API")
	}
	if cli.Broken {
		return fmt.Errorf("--broken is not supported because it is not relevant when using the GitHub API")
	}
	if cli.Candidates != 0 {
		return fmt.Errorf("--candidates is not supported. We always consider all candidates")
	}

	// Not yet implemented options.
	if cli.NoMatch {
		return fmt.Errorf("--no-match is not implemented")
	}
	if cli.NoExclude {
		return fmt.Errorf("--no-exclude is not implemented")
	}
	if cli.Debug {
		return fmt.Errorf("--debug is not implemented")
	}

	for _, m := range cli.Match {
		g, err := glob.Compile(m)
		if err != nil {
			return err
		}
		cli.matchers = append(cli.matchers, g)
	}

	for _, e := range cli.Exclude {
		g, err := glob.Compile(e)
		if err != nil {
			return err
		}
		cli.excluders = append(cli.excluders, g)
	}

	for _, m := range cli.RegexMatch {
		r, err := regexp.Compile(m)
		if err != nil {
			return err
		}
		cli.regexMatchers = append(cli.regexMatchers, r)
	}

	for _, e := range cli.RegexExclude {
		r, err := regexp.Compile(e)
		if err != nil {
			return err
		}
		cli.regexExcluders = append(cli.regexExcluders, r)
	}

	var err error
	if cli.Repo != "" {
		cli.repository, err = repository.Parse(cli.Repo)
	} else {
		cli.repository, err = repository.Current()
	}
	if err != nil {
		return err
	}

	cli.graphqlClient, err = api.NewGraphQLClient(api.ClientOptions{Host: cli.repository.Host})
	if err != nil {
		return err
	}

	for _, commitish := range cli.Commitish {
		var out string
		out, err = cli.runCommitish(ctx, commitish)
		if err != nil {
			return err
		}
		fmt.Fprintln(cli.stdout, out)
	}

	return nil
}

func (c *cmd) distance(node *refNode) int {
	if c.Contains {
		return node.Compare.BehindBy
	}
	return node.Compare.AheadBy
}

const minAbbrev = 4

func (c *cmd) runCommitish(ctx context.Context, commitish string) (string, error) {
	sha, err := c.getSha(ctx, commitish)
	if err != nil {
		return "", err
	}

	abbrevSha := sha
	if c.Abbrev != nil && *c.Abbrev != 0 {
		abbrev := *c.Abbrev
		if abbrev < minAbbrev {
			abbrev = minAbbrev
		}
		if abbrev < len(abbrevSha) {
			abbrevSha = abbrevSha[:abbrev]
		}
	}

	prefix := "refs/tags/"
	if c.All {
		prefix = "refs/"
	}
	refs, err := c.getAllRefs(ctx, commitish, prefix)
	if err != nil {
		return "", err
	}
	filtered := make([]refNode, 0, len(refs))
	for _, node := range refs {
		excludeStatus := githubv4.ComparisonStatusBehind
		if c.Contains {
			excludeStatus = githubv4.ComparisonStatusAhead
		}
		if !c.match(node.Name) ||
			node.Compare.Status == githubv4.ComparisonStatusDiverged ||
			node.Compare.Status == excludeStatus {
			continue
		}
		if !c.Tags && !c.All && node.Target.Typename == "Commit" {
			continue
		}
		filtered = append(filtered, node)
	}

	if len(filtered) == 0 {
		if c.ExactMatch {
			return "", fatalf("no tag exactly matches '%s'", commitish)
		}
		if c.Always {
			return abbrevSha, nil
		}
		return "", fatalf("No tags can describe '%s'\nTry --always, or create some tags.", commitish)
	}

	sort.Slice(filtered, func(i, j int) bool {
		if c.distance(&filtered[i]) != c.distance(&filtered[j]) {
			return c.distance(&filtered[i]) < c.distance(&filtered[j])
		}
		// tags first. this only matters when --all is specified
		if strings.HasPrefix(filtered[i].Name, "tags/") != strings.HasPrefix(filtered[j].Name, "tags/") {
			return strings.HasPrefix(filtered[i].Name, "tags/")
		}
		// annotated tags first
		iIsAnnotatedTag := filtered[i].Target.Typename == "Tag"
		jIsAnnotatedTag := filtered[j].Target.Typename == "Tag"
		if iIsAnnotatedTag != jIsAnnotatedTag {
			return iIsAnnotatedTag
		}
		// for annotated tags, newest date first
		if iIsAnnotatedTag {
			return filtered[i].Target.Tag.Tagger.Date.Time.After(filtered[j].Target.Tag.Tagger.Date.Time)
		}
		// everything else is sorted by name
		return filtered[i].Name < filtered[j].Name
	})

	result := filtered[0]
	output := fmt.Sprintf("%s-%d-g%s", result.Name, c.distance(&result), abbrevSha)
	if !c.Long && c.distance(&result) == 0 {
		output = result.Name
	}
	return output, nil
}

func (c *cmd) getSha(ctx context.Context, commitish string) (string, error) {
	var query struct {
		Repository struct {
			Object struct {
				Oid string
			} `graphql:"object(expression: $commitish)"`
		} `graphql:"repository(name: $repoName, owner: $owner)"`
	}
	variables := map[string]any{
		"commitish": githubv4.String(commitish),
		"repoName":  githubv4.String(c.repository.Name),
		"owner":     githubv4.String(c.repository.Owner),
	}

	err := c.graphqlClient.QueryWithContext(ctx, "", &query, variables)
	if err != nil {
		return "", fatalErr(err)
	}
	oid := query.Repository.Object.Oid
	if oid == "" {
		return "", fatalf("Not a valid object name %s", commitish)
	}
	return oid, nil
}

func (c *cmd) match(name string) bool {
	if c.All {
		_, name, _ = strings.Cut(name, "/")
	}
	for _, e := range c.excluders {
		if e.Match(name) {
			return false
		}
	}
	for _, e := range c.regexExcluders {
		if e.MatchString(name) {
			return false
		}
	}
	if len(c.matchers) == 0 && len(c.regexMatchers) == 0 {
		return true
	}
	for _, m := range c.matchers {
		if m.Match(name) {
			return true
		}
	}
	for _, m := range c.regexMatchers {
		if m.MatchString(name) {
			return true
		}
	}
	return false
}

type refNode struct {
	Name    string
	Prefix  string
	Compare struct {
		AheadBy  int
		BehindBy int
		Status   githubv4.ComparisonStatus
	} `graphql:"compare(headRef: $head)"`
	Target struct {
		Typename string `graphql:"__typename"`
		Tag      struct {
			Tagger struct {
				Date githubv4.DateTime
			}
		} `graphql:"... on Tag"`
	} `graphql:"target"`
}

func (c *cmd) getAllRefs(ctx context.Context, commitish, prefix string) ([]refNode, error) {
	var query struct {
		Repository struct {
			Refs struct {
				PageInfo struct {
					HasNextPage bool
					EndCursor   githubv4.String
				}
				Nodes []refNode
			} `graphql:"refs(first: 100, after: $afterCursor, refPrefix: $refPrefix)"`
		} `graphql:"repository(name: $repoName, owner: $owner)"`
	}
	variables := map[string]any{
		"head":        githubv4.String(commitish),
		"repoName":    githubv4.String(c.repository.Name),
		"owner":       githubv4.String(c.repository.Owner),
		"refPrefix":   githubv4.String(prefix),
		"afterCursor": (*githubv4.String)(nil),
	}
	if c.All {
		variables["refPrefix"] = githubv4.String("refs/")
	}
	var refs []refNode
	for {
		err := c.graphqlClient.QueryWithContext(ctx, "", &query, variables)
		if err != nil {
			return nil, fatalErr(err)
		}
		refs = append(refs, query.Repository.Refs.Nodes...)
		if !query.Repository.Refs.PageInfo.HasNextPage {
			break
		}
		variables["afterCursor"] = githubv4.NewString(query.Repository.Refs.PageInfo.EndCursor)
	}
	return refs, nil
}
