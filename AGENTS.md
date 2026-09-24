# Agent guidance

This repository is a small public Go reference CLI for provisioning Tailscale edge devices. Keep changes focused, idiomatic, and easy to review. Prefer correctness and security over adding features or abstractions.

## Technical work

- Check current official Tailscale documentation when relying on API, key, route-approval, or CLI behavior. State assumptions clearly; distinguish current recommended choices from historical context.
- Do not invent or infer historical facts about past IoT project. Use only documented project context, and do not copy internal prompts, transcripts, or private planning material into repository files.
- Keep the Tailscale API behind a small, testable boundary. Unit and integration tests must use mocks or local test servers; never require live credentials or contact a real tailnet.
- Never print, log, expose in errors, or commit OAuth credentials, auth keys, or other secrets. Sanitize subprocess and API failures.
- Avoid unnecessary dependencies, frameworks, and systems. Keep changes within the smallest relevant scope.

## Before completing a change

- Format Go files with `gofmt`.
- Run `go test ./...` and `go vet ./...` when applicable; report any checks not run.
- Review the diff for secrets, excess complexity, unsafe failure paths, and unsupported Tailscale API or CLI assumptions.
