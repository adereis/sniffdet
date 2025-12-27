# Sniffdet

Legacy C project (2002-2003) being modernized as a learning exercise.

## Workflow

**Educational approach**: Before making changes, explain the old way vs new way
and why practices evolved. Prioritize understanding over speed.

## Technical

- **libnet 1.0.2a**: Vendored in `third_party/libnet/` (API incompatible with 1.1+)
- **libpcap, pthreads**: System libraries
- **Build**: CMake 3.31+, Linux primary
- **Test**: `cd build && ctest --output-on-failure` (CMocka)
- **Roadmap**: See `doc/MODERNIZATION.md`

## Standards

- C11 (GNU extensions OK)
- `<stdint.h>` types over legacy (`uint8_t` not `u_char`)
- Modern include guards (no leading underscores)

## Commits

Architectural changes: include historical context and rationale in body.
Small fixes: concise messages OK.
