# gh-describe

__gh-describe__ is a command line tool that works like `git describe` but using the GitHub API instead of a local git
repository. It can be used as an extension for [gh](https://cli.github.com/) or as a standalone tool.

## Differences from git describe

- `gh-describe` uses the GitHub API instead of a local git repository allowing you to describe a commit that you don't
  have cloned locally.
- `gh-describe` outputs the full sha of the commit unless you use the `--abbrev` flag because it is not able to
  calculate the correct abbreviated sha without knowing all commit shas in the repository.
- `gh-describe` always considers all refs as candidates instead of limiting to 10 because GitHub's API does not offer a
  way to replicate git's behavior for choosing candidate refs.
- Non-zero status codes may be different. `gh-describe` exits 1 on usage vs 129 for `git`. Aside from that `gh-describe`
  attempts to match `git`'s exit codes, but it's not guaranteed.
- `gh-describe` does not support blob references.
- `gh-describe` only works as well as the GitHub API. It often fails on very large repositories such as 
   github.com/git/git.
- `--debug` output is entirely different.

### Enhancements

- `--match-regex` and `exclude-regex` are like `--match` and `--exclude` but
  use [re2](https://github.com/google/re2/wiki/Syntax) syntax instead of glob(7).
- `--match-semver` causes `gh-describe` to only consider tags that match the given semver range.
  Use `--match-semver='*'` to match all non-prerelease tags. or `--match-semver='*-0'` to match all semver tags.
- `--semver-prefix` is used with `--match-semver` and causes `gh-describe` to strip the prefix from the semver tag
  before comparing it to the semver range.

### Unsupported flags

- `--dirty` and `--broken` don't make sense when using the GitHub API instead of a local git repository.
- `--candidates` is not needed because gh-describe always considers all refs as candidates.
- `--first-parent` is not supported because it isn't supported by GitHub's API.
- `--no-match` and `--no-exclude` are not implemented because I don't have a use case for them and they would be
  non-trivial to implement. If you need them, open an issue and I'll consider it.

## Installation

### standalone

Download the binary for your platform from
the [latest release](https://github.com/WillAbides/gh-describe/releases/latest).

Or use go install:

```shell
go install github.com/willabides/gh-describe@latest
```

### gh extension

```shell
gh extension install willabides/gh-describe
```

## Usage

<!--- everything between the next line and the "end usage output" comment is generated by script/generate-readme --->
<!--- start usage output --->

```
Usage: gh-describe [<commit-ish> ...]

Like git-describe, but for GitHub repositories. See https://github.com/WillAbides/gh-describe for
more details.

The command finds the most recent tag that is reachable from a commit. If the tag points to
the commit, then only the tag is shown. Otherwise, it suffixes the tag name with the number of
additional commits on top of the tagged object and the abbreviated object name of the most recent
commit. The result is a "human-readable" object name which can also be used to identify the commit
to other git commands.

By default (without --all or --tags) gh-describe only shows annotated tags.

Arguments:
  [<commit-ish> ...]    Commit-ish object names to describe. Defaults to HEAD if omitted.

Flags:
  -h, --help                             Show context-sensitive help.
      --version                          Show gh-describe version
  -R, --repo=STRING                      Select another repository using the [HOST/]OWNER/REPO
                                         format
      --contains                         Instead of finding the tag that predates the commit, find
                                         the tag that comes after the commit, and thus contains it.
                                         Automatically implies --tags.
      --all                              Instead of using only the annotated tags, use any ref found
                                         in refs/ namespace. This option enables matching any known
                                         branch or lightweight tag.
      --tags                             Instead of using only the annotated tags, use any tag found
                                         in refs/tags namespace. This option enables matching a
                                         lightweight (non-annotated) tag.
      --long                             Always output the long format (the tag, the number of
                                         commits and the abbreviated commit name) even when it
                                         matches a tag. This is useful when you want to see parts
                                         of the commit object name in "describe" output, even when
                                         the commit in question happens to be a tagged version.
                                         Instead of just emitting the tag name, it will describe
                                         such a commit as v1.2-0-gdeadbee (0th commit since tag v1.2
                                         that points at object deadbee....).
      --abbrev=<n>                       Instead of using the full sha1, use n digits, to represent
                                         the sha1. Minimum length is 4. An n of 0 will suppress long
                                         format, only showing the closest tag.
      --exact-match                      Only output exact matches (a tag directly references the
                                         supplied commit). This has no relation to the --match*
                                         options.
      --match=<pattern>,...              Only consider tags matching the given glob(7) pattern,
                                         excluding the "refs/tags/" prefix. If used with --all,
                                         it also considers local branches matching the pattern
                                         excluding "refs/heads/" prefix; references of other
                                         types are never considered. If given multiple times,
                                         a list of patterns will be accumulated, and tags matching
                                         any of the patterns will be considered. When combined
                                         with --match-regex and/or --match-semver a tag will be
                                         considered when it matches any of the --match* patterns.
      --exclude=<pattern>,...            Do not consider tags matching the given glob(7) pattern,
                                         excluding the "refs/tags/" prefix. If used with --all, it
                                         also does not consider local branches matching the pattern,
                                         excluding "refs/heads/" prefix; references of other types
                                         are never considered. If given multiple times, a list of
                                         patterns will be accumulated and tags matching any of the
                                         patterns will be excluded. When combined with --match a tag
                                         will be considered when it matches at least one --match
                                         pattern and does not match any of the --exclude patterns.
      --match-regex=<regex>,...          Only consider tags matching the given regular expression
                                         (re2/go flavor), excluding the "refs/tags/" prefix.
                                         If used with --all, it also considers local branches
                                         matching the pattern excluding "refs/heads/" prefix;
                                         references of other types are never considered. If given
                                         multiple times, a list of patterns will be accumulated,
                                         and tags matching any of the patterns will be considered.
                                         When combined with --match and/or --match-semver a tag will
                                         be considered when it matches any of the --match* patterns.
      --exclude-regex=<regex>,...        Do not consider tags matching the given regular expression
                                         (re2/go flavor), excluding the "refs/tags/" prefix. If
                                         used with --all, it also does not consider local branches
                                         matching the pattern, excluding "refs/heads/" prefix;
                                         references of other types are never considered. If given
                                         multiple times, a list of patterns will be accumulated
                                         and tags matching any of the patterns will be excluded.
                                         When combined with --match a tag will be considered when it
                                         matches at least one --match pattern and does not match any
                                         of the --exclude patterns.
      --match-semver=<constraint>,...    Only consider tags that satisfy the given semver
                                         constraint, excluding the "refs/tags/" prefix. If used
                                         with --all, it also considers local branches matching the
                                         pattern excluding "refs/heads/" prefix; references of other
                                         types are never considered. If given multiple times, a list
                                         of constraints will be accumulated, and tags satisfying any
                                         of the constraints will be considered. When combined with
                                         --match and/or --match-regex a tag will be considered when
                                         it matches any of the --match* patterns.
      --semver-prefix=<prefix>           Prefix to use when matching semver constraints.
                                         Before matching, the prefix is stripped from the tag name.
                                         Ignored unless --match-semver is used.
      --always                           Show commit object as fallback.
      --debug                            Verbosely display information about the searching strategy
                                         being employed to standard error. The tag name will still
                                         be printed to standard out.
```

<!--- end usage output --->
