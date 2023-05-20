package main

import (
	"context"
	"fmt"
	"io"
	"math"
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

func main() {
	var cli cmd
	parser := kong.Parse(&cli, kongVars, kong.Name("gh-describe"))
	k, err := parser.Parse(os.Args[1:])
	parser.FatalIfErrorf(err)
	ctx := context.Background()
	cli.stdout = os.Stdout
	cli.stderr = os.Stderr
	err = run(ctx, &cli)
	k.FatalIfErrorf(err)
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
		return fmt.Errorf("--no-match is not yet implemented")
	}
	if cli.NoExclude {
		return fmt.Errorf("--no-exclude is not yet implemented")
	}
	if cli.Debug {
		return fmt.Errorf("--debug is not yet implemented")
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
		err = cli.runCommitish(ctx, commitish)
		if err != nil {
			return err
		}
	}

	return nil
}

const minAbbrev = 4

func (c *cmd) runCommitish(ctx context.Context, commitish string) error {
	sha, err := c.getSha(ctx, commitish)
	if err != nil {
		return err
	}

	abbrevSha := sha
	if c.Abbrev != nil && *c.Abbrev != 0 {
		abbrev := *c.Abbrev
		if abbrev < minAbbrev {
			abbrev = minAbbrev
		}
		abbrevSha = abbrevSha[:abbrev]
	}

	prefix := "refs/tags/"
	if c.All {
		prefix = "refs/"
	}
	refs, err := c.getAllRefs(ctx, commitish, prefix)
	if err != nil {
		return err
	}
	minDistance := math.MaxInt32
	winners := make([]refNode, 0, len(refs))
	for _, node := range refs {
		distance := node.Compare.AheadBy
		excludeStatus := githubv4.ComparisonStatusBehind
		if c.Contains {
			distance = node.Compare.BehindBy
			excludeStatus = githubv4.ComparisonStatusAhead
		}
		if !c.match(node.Name) {
			continue
		}
		if node.Compare.Status == githubv4.ComparisonStatusDiverged {
			continue
		}
		if !c.Tags && !c.All && node.Target.Typename == "Commit" {
			continue
		}
		if node.Compare.Status == excludeStatus {
			continue
		}
		if distance > minDistance {
			continue
		}
		if distance < minDistance {
			minDistance = distance
			winners = winners[:0]
		}
		winners = append(winners, node)
	}

	if len(winners) == 0 {
		if c.Always {
			fmt.Fprintln(c.stdout, abbrevSha)
			return nil
		}
		return fmt.Errorf("No tags can describe '%s'\nTry --always, or create some tags.", commitish)
	}

	sort.Slice(winners, func(i, j int) bool {
		// tags first
		if strings.HasPrefix(winners[i].Name, "tags/") != strings.HasPrefix(winners[j].Name, "tags/") {
			return strings.HasPrefix(winners[i].Name, "tags/")
		}
		return winners[i].Name < winners[j].Name
	})

	winner := winners[0]
	distance := winner.Compare.AheadBy
	if c.Contains {
		distance = winner.Compare.BehindBy
	}
	output := fmt.Sprintf("%s-%d-g%s", winner.Name, distance, abbrevSha)
	if !c.Long && distance == 0 {
		output = winner.Name
	}
	fmt.Fprintln(c.stdout, output)
	return nil
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
		return "", err
	}
	oid := query.Repository.Object.Oid
	if oid == "" {
		return "", fmt.Errorf("Not a valid object name %s", commitish)
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
			} `graphql:"refs(first: 100, after: $afterCursor, refPrefix: $refPrefix, orderBy: {field: TAG_COMMIT_DATE, direction: DESC})"`
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
			return nil, err
		}
		refs = append(refs, query.Repository.Refs.Nodes...)
		if !query.Repository.Refs.PageInfo.HasNextPage {
			break
		}
		variables["afterCursor"] = githubv4.NewString(query.Repository.Refs.PageInfo.EndCursor)
	}
	return refs, nil
}
