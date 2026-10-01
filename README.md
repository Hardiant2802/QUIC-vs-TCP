# QUIC-vs-TCP

Week 8 automation for comparing HTTP/2 over TCP and HTTP/3 over QUIC in an Ubuntu/WSL lab. The runner creates temporary network namespaces, applies delay and packet loss, captures packets, records raw results, and produces CSV summaries and plots.

Start with the [Week 8 run guide](docs/week-08/README.md). It includes setup, commands for each experiment, and output descriptions. [KIEM-THU.md](docs/week-08/KIEM-THU.md) records the available functional checks and their dates.

The repository contains the Caddy and HTTP/3 curl binaries used by the runner, plus the test objects and 64 MiB migration input. Migration support is built locally by `scripts/setup-week8-migration.sh`. Experiment output, packet captures, TLS key logs, and build artifacts are not part of the source repository.