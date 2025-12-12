# Sniffdet - Developer/AI Guide

## Project Context

This is a **legacy C project from 2002-2003** being modernized as a learning exercise.
The goal is to understand how C development practices have evolved over 20+ years.

## Interaction Workflow

**This project uses an educational, step-by-step approach:**

1. **Before each change**: Explain what's being changed and why
   - Compare how things worked before (the "old way")
   - Describe how practices evolved over time
   - Explain why the new approach is better
   - Give examples of problems the old approach caused

2. **Then make the change**: Implement the discussed modification

3. **Move slowly**: Prefer depth of understanding over speed of implementation

This workflow applies to all modernization work: build system, code style,
library migrations, tooling setup, etc.

## Technical Details

### Dependencies
- **libnet 1.0.2a** - Vendored in `third_party/libnet/` (ancient, API incompatible with 1.1+)
- **libpcap** - System library (still actively maintained, stable API)
- **pthreads** - POSIX threads

### Build System
- Migrating from Autotools to modern CMake (3.31+)
- Target: Linux (primary), BSD (secondary/untested)

### Project Structure
```
sniffdet/
├── src/
│   ├── lib/          # libsniffdet - the detection library
│   └── *.c           # sniffdet CLI tool
├── third_party/
│   └── libnet/       # Vendored libnet 1.0.2a
├── cmake/            # CMake modules (if needed)
└── doc/              # Documentation
```

## Commit Message Guidelines

For significant changes, especially during modernization, commit messages should be
**educational and serve as documentation**:

1. **Subject line**: Brief summary (50-72 chars)
2. **Body**: Explain the "why" and include:
   - Historical context (how things worked before)
   - What changed in the ecosystem over time
   - Why the new approach is better
   - Common problems the old approach caused
   - References to relevant resources (papers, docs, tools)

This makes the git history a learning resource. When someone runs `git log` or
`git blame`, they understand not just *what* changed but *why* it matters.

Bugfixes and small changes can have concise messages. But architectural changes,
build system updates, and modernization efforts deserve thorough explanations.

Think: "Would this commit message help someone understand this codebase in 10 years?"

## Coding Standards (Target)

As we modernize, we aim for:
- C11 standard (with GNU extensions where needed)
- `<stdint.h>` types (`uint8_t`, `uint32_t`) instead of legacy types (`u_char`, `ulong`)
- Modern include guards (no leading underscores)
- Consistent formatting (clang-format, to be configured)
