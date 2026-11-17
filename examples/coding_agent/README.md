# Example: coding agent

An agent that reads a repository and edits files. Comments, docstrings, commit messages,
issue text and dependency READMEs are all attacker-reachable surfaces.

## Run it

```bash
python examples/coding_agent/vulnerable.py
python examples/coding_agent/protected.py
```

## What you should see

The vulnerable agent repeats the injected instruction and issues a shell call. The
protected agent flags the file, wraps the content as data, and the tool gate refuses
`run_shell` outright while routing `write_file` to a (declining) human approver.

## Why this carrier is nasty

* A comment is *supposed* to be ignored by the compiler, so reviewers skim it.
* Agents are expected to act on repository content, so "the data made me do it" is a
  normal-looking failure.
* The payload can be one line in a 400-file diff, and code review attention is finite.

## What actually protects you here

1. **No shell tool for the agent at all**, or one that runs in a container with a
   read-only mount and no network. This is the only control that survives a model that
   ignores every prompt.
2. **Deny-by-default tool gate** with an explicit allow-list per task.
3. **Human approval for writes**, showing the diff to the reviewer.
4. Scanning, to catch the lazy version of the attack and to give the reviewer a signal.

## The linter trap

The sample payload asks the agent to "disable the linter" as well. Any request that
reduces your ability to detect the next request is a red flag. Treat "disable logging",
"skip review" and "turn off the checks" as high severity, not housekeeping.

## Production notes

* Run agents on a branch, not on `main`, and require a PR for the merge.
* Pin the tool-call budget per task; a loop that keeps calling tools is a symptom.
* Keep secrets out of the working tree so a shell call cannot read them.
