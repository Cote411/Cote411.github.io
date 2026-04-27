# TinyCC Cybersecurity Lab

A Docker-based Linux environment for studying and experimenting with the
**Tiny C Compiler (TinyCC)** on macOS.

---

## Directory structure (this repo)

```
tinyCC/
├── Dockerfile        ← Ubuntu 22.04 image with all dependencies
├── setup.sh          ← Runs inside the container: clones, builds, tests
├── login.c           ← Baseline C program copied into the container
├── run.sh            ← macOS helper: build image & launch container
└── README.md
```

After `setup.sh` runs, the container will have:

```
~/trustlab/
├── tinycc-clean/     ← unmodified TinyCC clone  (DO NOT MODIFY)
├── tinycc-infected/  ← your experiment copy
└── workspace/
    ├── login.c
    └── login         ← compiled binary
```

---

## Prerequisites (macOS)

| Requirement | Install |
|-------------|---------|
| Docker Desktop | <https://www.docker.com/products/docker-desktop/> |
| Git | `xcode-select --install` or Homebrew |

Make sure Docker Desktop is running before proceeding.

---

## Quick start

```bash
# 1. Clone or open this repo
cd /path/to/tinyCC

# 2. Make scripts executable
chmod +x run.sh setup.sh

# 3a. Non-interactive: builds image, runs full setup, prints results, then exits
./run.sh setup

# 3b. Interactive: builds image, drops you into a bash shell
./run.sh
#   Inside the container, run:
bash ~/setup.sh
```

---

## Step-by-step explanation

### Step 1 — Docker image (Ubuntu 22.04)

`docker build` reads `Dockerfile` and produces an image named `tinycc-lab`.

The image installs:
- `build-essential` — GCC toolchain needed to bootstrap TinyCC
- `git` — to clone the TinyCC repository
- `make` — the TinyCC build system
- `python3` — used by TinyCC's test suite

A non-root user `labuser` owns all lab files for safer operation.

---

### Step 2 & 3 — Clone TinyCC twice

```bash
# Reference copy — never modify this
git clone --depth=1 https://repo.or.cz/tinycc.git ~/trustlab/tinycc-clean

# Experiment copy — all changes go here
git clone --depth=1 https://repo.or.cz/tinycc.git ~/trustlab/tinycc-infected
```

`--depth=1` fetches only the latest commit, keeping the download small.

---

### Step 4 — Build TinyCC from source

```bash
cd ~/trustlab/tinycc-clean
./configure          # detects host compiler, generates Makefile vars
make -j$(nproc)     # compiles tcc + its runtime library (libtcc1.a)
```

Repeat for `tinycc-infected`.

After a successful build the `tcc` binary lives **directly in the source
directory** (not in `bin/`). There is no need to run `make install`.

---

### Step 5 — login.c

```c
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) { fprintf(stderr, "Usage: %s <username>\n", argv[0]); return 1; }
    if (strcmp(argv[1], "root") == 0) { printf("Access granted\n"); return 0; }
    printf("Access denied\n"); return 1;
}
```

Simple baseline: only `"root"` is accepted.

---

### Step 6 — Compile and test with TinyCC

#### Why `-B <dir>`?

TinyCC needs to locate its own runtime files — primarily `libtcc1.a` — to
link programs. When you run the compiler directly from its build directory
(**before** `make install`), those files are in the same directory as the
`tcc` binary, not in `/usr/local/lib/tcc/`. The `-B` flag tells TCC exactly
where to look:

```
-B <dir>   Set TCC's library/include search path to <dir>
```

Without `-B .` (or `-B <full-path>`), TCC will fail with:
```
tcc: error: file 'libtcc1.a' not found
```

#### Compile command

```bash
~/trustlab/tinycc-infected/tcc \
    -B ~/trustlab/tinycc-infected \
    ~/trustlab/workspace/login.c \
    -o ~/trustlab/workspace/login
```

#### Verify behaviour

```bash
~/trustlab/workspace/login root    # → "Access granted: welcome, root."  exit 0
~/trustlab/workspace/login alice   # → "Access denied: unknown user..."   exit 1
~/trustlab/workspace/login         # → usage message                       exit 1

# Check exit codes explicitly
echo $?
```

---

## Useful commands inside the container

```bash
# Confirm TinyCC version
~/trustlab/tinycc-infected/tcc -v

# Compile any C file
~/trustlab/tinycc-infected/tcc -B ~/trustlab/tinycc-infected <file.c> -o <output>

# Run TinyCC's own test suite (optional)
cd ~/trustlab/tinycc-infected && make test

# Diff clean vs infected (to review your changes later)
diff -rq ~/trustlab/tinycc-clean ~/trustlab/tinycc-infected \
    --exclude='*.o' --exclude='*.a' --exclude='tcc'
```

---

## Constraints reminder

- **Do NOT** modify anything in `~/trustlab/tinycc-clean`
- **Do NOT** add exploit code, shellcode, or malicious payloads
- All changes to TinyCC source go in `~/trustlab/tinycc-infected` only
- This lab is for educational/research purposes in a controlled environment

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `docker: command not found` | Install and start Docker Desktop |
| `git clone` fails | Check internet connectivity inside Docker; try `ping 8.8.8.8` |
| `tcc: error: file 'libtcc1.a' not found` | You forgot `-B <tinycc-dir>` |
| Build fails with `cc: not found` | `apt-get install -y build-essential` (already in Dockerfile) |
| Container exits immediately | Use `-it` flag with `docker run` |
