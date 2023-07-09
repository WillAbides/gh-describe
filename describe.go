package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/alecthomas/kong"
	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/gobwas/glob"
	"github.com/shurcooL/githubv4"
)

var version = "unknown"

const description = `Like git-describe, but for GitHub repositories. 
See https://github.com/WillAbides/gh-describe for more details.

The command finds the most recent tag that is reachable from a
commit. If the tag points to the commit, then only the tag is
shown. Otherwise, it suffixes the tag name with the number of
additional commits on top of the tagged object and the
abbreviated object name of the most recent commit. The result
is a "human-readable" object name which can also be used to
identify the commit to other git commands.

By default (without --all or --tags) gh-describe only shows
annotated tags.
`

var kongVars = kong.Vars{
	"commitish_help": `
Commit-ish object names to describe. Defaults to HEAD if omitted.
`,

	"all_help": `
Instead of using only the annotated tags, use any ref
found in refs/ namespace.  This option enables matching
any known branch or lightweight tag.
`,

	"tags_help": `
Instead of using only the annotated tags, use any tag
found in refs/tags namespace.  This option enables matching
a lightweight (non-annotated) tag.
`,

	"contains_help": `
Instead of finding the tag that predates the commit, find
the tag that comes after the commit, and thus contains it.
Automatically implies --tags.
`,

	"abbrev_help": `
Instead of using the full sha1, use n digits, to represent
the sha1.  Minimum length is 4. An n of 0 will suppress
long format, only showing the closest tag.
`,

	"exact_match_help": `
Only output exact matches (a tag directly references the supplied commit).
This has no relation to the --match* options.
`,

	"debug_help": `
Verbosely display information about the searching strategy
being employed to standard error.  The tag name will still
be printed to standard out.
`,

	"long_help": `
Always output the long format (the tag, the number of commits
and the abbreviated commit name) even when it matches a tag.
This is useful when you want to see parts of the commit object name
in "describe" output, even when the commit in question happens to be
a tagged version.  Instead of just emitting the tag name, it will
describe such a commit as v1.2-0-gdeadbee (0th commit since tag v1.2
that points at object deadbee....).
`,

	"match_help": `
Only consider tags matching the given glob(7) pattern,
excluding the "refs/tags/" prefix. If used with --all, it also
considers local branches matching the pattern excluding "refs/heads/" 
prefix; references of other types are never considered. If given
multiple times, a list of patterns will be accumulated, and tags
matching any of the patterns will be considered. When combined with
--match-regex and/or --match-semver a tag will be considered when it
matches any of the --match* patterns.
`,

	"exclude_help": `
Do not consider tags matching the given glob(7) pattern, excluding
the "refs/tags/" prefix. If used with --all, it also does not consider
local branches matching the pattern, excluding "refs/heads/" prefix;
references of other types are never considered. If given multiple times,
a list of patterns will be accumulated and tags matching any of the
patterns will be excluded. When combined with --match a tag will be
considered when it matches at least one --match pattern and does not
match any of the --exclude patterns.
`,

	"always_help": `
Show commit object as fallback.
`,

	"regex_match_help": `
Only consider tags matching the given regular expression (re2/go flavor),
excluding the "refs/tags/" prefix. If used with --all, it also
considers local branches matching the pattern excluding "refs/heads/" 
prefix; references of other types are never considered. If given
multiple times, a list of patterns will be accumulated, and tags
matching any of the patterns will be considered. When combined with
--match and/or --match-semver a tag will be considered when it
matches any of the --match* patterns.
`,

	"regex_exclude_help": `
Do not consider tags matching the given regular expression (re2/go flavor), 
excluding the "refs/tags/" prefix. If used with --all, it also does not 
consider local branches matching the pattern, excluding "refs/heads/" prefix;
references of other types are never considered. If given multiple times,
a list of patterns will be accumulated and tags matching any of the
patterns will be excluded. When combined with --match a tag will be
considered when it matches at least one --match pattern and does not
match any of the --exclude patterns.
`,

	"match_semver_help": `
Only consider tags that satisfy the given semver constraint,
excluding the "refs/tags/" prefix. If used with --all, it also
considers local branches matching the pattern excluding "refs/heads/"
prefix; references of other types are never considered. If given
multiple times, a list of constraints will be accumulated, and tags
satisfying any of the constraints will be considered. When combined
with --match and/or --match-regex a tag will be considered when it
matches any of the --match* patterns.
`,

	"semver_prefix_help": `
Prefix to use when matching semver constraints. Before matching, the
prefix is stripped from the tag name. Ignored unless --match-semver is used.
`,

	"repo_help": `
Select another repository using the [HOST/]OWNER/REPO format
`,

	"version_help": `
Show gh-describe version
`,

	"version": version,
}

type cmd struct {
	Version      kong.VersionFlag `kong:"help=${version_help}"`
	Repo         string           `kong:"short=R,help=${repo_help}"`
	Commitish    []string         `kong:"arg,name=commit-ish,default=HEAD,help=${commitish_help}"`
	Contains     bool             `kong:"help=${contains_help}"`
	All          bool             `kong:"help=${all_help}"`
	Tags         bool             `kong:"help=${tags_help}"`
	Long         bool             `kong:"help=${long_help}"`
	Abbrev       *int             `kong:"placeholder='<n>',help=${abbrev_help}"`
	ExactMatch   bool             `kong:"help=${exact_match_help}"`
	Match        []string         `kong:"placeholder=<pattern>,help=${match_help}"`
	Exclude      []string         `kong:"placeholder=<pattern>,help=${exclude_help}"`
	MatchRegex   []string         `kong:"placeholder=<regex>,help=${regex_match_help}"`
	ExcludeRegex []string         `kong:"placeholder=<regex>,help=${regex_exclude_help}"`
	MatchSemver  []string         `kong:"name=match-semver,placeholder=<constraint>,help=${match_semver_help}"`
	SemverPrefix string           `kong:"name=semver-prefix,placeholder=<prefix>,help=${semver_prefix_help}"`
	Always       bool             `kong:"help=${always_help}"`
	Debug        bool             `kong:"help=${debug_help}"`

	// Unsupported options from git-describe.
	// Here so we can output a friendlier error message.
	FirstParent bool `kong:"first-parent,hidden"`
	NoMatch     bool `kong:"no-match,hidden"`
	NoExclude   bool `kong:"no-exclude,hidden"`
	Dirty       bool `kong:"hidden"`
	Broken      bool `kong:"hidden"`
	Candidates  int  `kong:"hidden"`

	repository     repository.Repository
	graphqlClient  *api.GraphQLClient
	matchers       []glob.Glob
	excluders      []glob.Glob
	stdout         io.Writer
	stderr         io.Writer
	regexMatchers  []*regexp.Regexp
	regexExcluders []*regexp.Regexp
	semverMatchers []*semver.Constraints
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

	if cli.Abbrev != nil && *cli.Abbrev == 0 && cli.Long {
		return fatalf("--long is incompatible with --abbrev=0")
	}
	if cli.Contains {
		cli.Tags = true
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

	for _, m := range cli.MatchRegex {
		r, err := regexp.Compile(m)
		if err != nil {
			return err
		}
		cli.regexMatchers = append(cli.regexMatchers, r)
	}

	for _, e := range cli.ExcludeRegex {
		r, err := regexp.Compile(e)
		if err != nil {
			return err
		}
		cli.regexExcluders = append(cli.regexExcluders, r)
	}

	for _, m := range cli.MatchSemver {
		c, err := semver.NewConstraint(m)
		if err != nil {
			return err
		}
		cli.semverMatchers = append(cli.semverMatchers, c)
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
	if c.Abbrev != nil && *c.Abbrev == 0 {
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
			c.debug("match: %q excluded by glob %q", name, e)
			return false
		}
	}
	for _, e := range c.regexExcluders {
		if e.MatchString(name) {
			c.debug("match: %q excluded by regex %q", name, e)
			return false
		}
	}
	if len(c.matchers) == 0 && len(c.regexMatchers) == 0 && len(c.semverMatchers) == 0 {
		c.debug("match: %q included by default", name)
		return true
	}
	for _, m := range c.matchers {
		if m.Match(name) {
			c.debug("match: %q included by glob %q", name, m)
			return true
		}
	}
	for _, m := range c.regexMatchers {
		if m.MatchString(name) {
			c.debug("match: %q included by regex %q", name, m)
			return true
		}
	}
	semverString, hasPrefix := strings.CutPrefix(name, c.SemverPrefix)
	if !hasPrefix {
		c.debug("match: %q excluded by semver prefix %q", name, c.SemverPrefix)
		return false
	}
	v, err := semver.StrictNewVersion(semverString)
	if err != nil {
		c.debug("match: %q excluded by semver %q", name, err)
		return false
	}
	for _, m := range c.semverMatchers {
		valid, reasons := m.Validate(v)
		// use reasons when implementing --debug
		_ = reasons
		if valid {
			c.debug("match: %q included by semver %q", name, m)
			return true
		}
	}
	c.debug("match: %q excluded by not matching anything", name)
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

func (c *cmd) debug(format string, args ...interface{}) {
	if c.Debug {
		if !strings.HasSuffix(format, "\n") {
			format += "\n"
		}
		fmt.Fprintf(os.Stderr, format, args...)
	}
}
