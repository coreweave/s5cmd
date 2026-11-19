# Contributing to `s5cmd`

A big welcome 👋 and thank you for considering contributing to `s5cmd` open source project.

  1. [About this document](#about-this-document)
  2. [Getting the code](#getting-the-code)
  3. [Testing](#testing)
  4. [Submitting a Pull Request](#submitting-a-pull-request)


## About this document

This document is a guide for developers interested in contributing to `s5cmd`.

## Getting the code

To download the source code of `s5cmd` you will need `git`. There are multiple ways of installing `git` depending on your operating system. This [document](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) is a good starting point if you don't have `git` installed already.

Clone `coreweave/s5cmd`, create a branch for your changes, and push it to the repository. Pull request creation is limited to collaborators.

## Testing

### Running the tests

`s5cmd` has both unit tests and integration tests. Unit tests are used to verify the correctness of units (ie functions), integration tests are used to prevent regressions.

While running integration tests `s5cmd` is built and is ran against a fake (in memory) s3 implementation.

We strongly encourage you to write tests for your proposed changes. You can run the tests with the following command:

```
make test
```

For the bounded live CLI suite, see [storage acceptance setup](doc/storage-acceptance.md). Live tests require explicit configuration and use renewable profile credentials; ordinary test runs use fake storage.

### Running static code analysis tools

Here are the list of tools that are used to check the sanity of the code at compile time:
 - [go vet](https://pkg.go.dev/cmd/vet) 
 - [gofmt](https://blog.golang.org/gofmt) go code formatter
 - [staticcheck](https://staticcheck.io/) go linter
 - [unparam](https://github.com/mvdan/unparam) finds unused parameters

`make check` command runs all the checks.

Builds use Go modules pinned by `go.mod` and verified by `go.sum`. Credential process execution and explicit profile safeguards live in `storage`; dependencies are unmodified. After updating dependencies, run `go mod verify` and the credential regressions in `storage` and `e2e`.

### Performance

While adding your changes and testing your changes, it would be good to remember that `s5cmd`'s goal is to be the fastest s3 client with a rich set of functionality. Here are some important things to keep in mind:

- Avoid making unnecessary s3 api calls.
- If your workload can be made faster by concurrent execution of several tasks use concurrency constructs.


## Submitting a Pull Request

Target `main` in `coreweave/s5cmd`. CI runs build, test, and QA checks for pull requests and merges into that branch. The CI matrix runs tests on Linux and builds binaries for Linux, macOS, and Windows. Ordinary merges update the release PR when release automation is active.

Release PRs use Conventional Commits and require protected storage acceptance before publication. See [release setup and operation](doc/releases.md).
