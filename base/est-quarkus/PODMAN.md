# Podman Development Environment for EST Quarkus PoC

This directory contains a complete Podman-based development environment for building and running the EST Quarkus Proof of Concept.

## Why Podman?

- **Rootless**: Run containers without root privileges
- **Daemonless**: No background service required
- **Docker-compatible**: Uses OCI containers, compatible with Docker images
- **Red Hat ecosystem**: Natural fit for Fedora-based PKI development
- **Security**: Better isolation and security model

## Prerequisites

### Install Podman

**Fedora/RHEL/CentOS:**
```bash
sudo dnf install podman
```

**macOS:**
```bash
brew install podman

# Initialize Podman machine (macOS only)
podman machine init
podman machine start
```

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install podman
```

**Verify installation:**
```bash
podman --version
# Should show: podman version 4.0.0 or higher
```

### Apple Silicon (M1/M2/M3) Users - Important Note

⚠️ **ARM64 Limitation**: JSS and LDAP SDK are only available for x86_64 architecture. If you're on Apple Silicon:

**Option 1: Review Environment (Recommended)**
- Use the ARM64 Containerfile (automatically selected)
- Review code, study patterns, read documentation
- Cannot build/run full PKI stack

**Option 2: Platform Emulation**
```bash
# Build for x86_64 with emulation (slower but works)
podman build --platform linux/amd64 \
    -f base/est-quarkus/Containerfile \
    -t pki-est-quarkus-dev:latest-x86 .

# Run with emulation
podman run --platform linux/amd64 ...
```

**Option 3: Remote x86_64 Machine**
- Use a cloud VM (AWS, GCP, Azure)
- Use a physical x86_64 Linux machine

The scripts automatically detect ARM64 and guide you through the options.

## Quick Start

### 1. Build the Container Image

```bash
cd base/est-quarkus
./podman-build.sh
```

This will:
- Build a Fedora 40-based container
- Install Java 17, Maven, and all PKI dependencies
- Install JSS and LDAP SDK from COPR
- Build the parent PKI modules
- Create an image tagged `pki-est-quarkus-dev:latest`

Build time: ~10-15 minutes (first time)

### 2. Run the Development Environment

```bash
./podman-run.sh
```

This will:
- Start an interactive container
- Mount your local PKI source at `/workspace/pki`
- Expose ports 8080 (HTTP), 8443 (HTTPS), 5005 (debug)
- Drop you into a bash shell inside the container

### 3. Build and Run the PoC (Inside Container)

Once inside the container:

```bash
# Option A: Quick build and run
./quarkus-dev.sh

# Option B: Manual build
cd /workspace/pki/base/est-quarkus
mvn clean package
mvn quarkus:dev

# Option C: Just compile
mvn clean compile
```

### 4. Access the Application

From your **host machine** browser:

- **Quarkus Dev UI**: http://localhost:8080/q/dev
- **Health Check**: http://localhost:8080/q/health
- **Metrics**: http://localhost:8080/q/metrics
- **EST API**: https://localhost:8443/rest/cacerts

## Container Scripts

### podman-build.sh

Builds the container image with all dependencies.

**Usage:**
```bash
./podman-build.sh
```

**What it does:**
- Creates image from Containerfile
- Installs system packages (Java, Maven, gcc, cmake)
- Adds PKI dependencies from COPR (JSS, LDAP SDK)
- Builds parent PKI modules
- Tags as `pki-est-quarkus-dev:latest`

### podman-run.sh

Runs the development container interactively.

**Usage:**
```bash
./podman-run.sh
```

**Features:**
- Mounts local source with `:Z` for SELinux compatibility
- Exposes ports: 8080 (HTTP), 8443 (HTTPS), 5005 (debug)
- Removes container on exit (`--rm`)
- Sets working directory to `/workspace/pki/base/est-quarkus`

### quarkus-dev.sh

Convenience script to run Quarkus in dev mode (use inside container).

**Usage (inside container):**
```bash
./quarkus-dev.sh
```

**Features:**
- Checks if parent PKI is built, builds if needed
- Runs `mvn quarkus:dev` with correct settings
- Binds to 0.0.0.0 for container access
- Enables remote debugging on port 5005

## Common Workflows

### Workflow 1: Quick Development Session

```bash
# On host
./podman-run.sh

# Inside container
./quarkus-dev.sh

# Browse to http://localhost:8080/q/dev
```

### Workflow 2: Full Build from Scratch

```bash
# On host
./podman-build.sh
./podman-run.sh

# Inside container
cd /workspace/pki
./build.sh dist

cd base/est-quarkus
mvn clean package
mvn quarkus:dev
```

### Workflow 3: Edit Code Locally, Test in Container

```bash
# Terminal 1 (host) - Edit code
vim base/est-quarkus/src/main/java/org/dogtagpki/est/quarkus/ESTFrontendQuarkus.java

# Terminal 2 (container) - Run Quarkus with live reload
./podman-run.sh
./quarkus-dev.sh

# Changes automatically reload!
```

### Workflow 4: Run Tests

```bash
# Inside container
cd /workspace/pki/base/est-quarkus

# Unit tests
mvn test

# Integration tests
mvn verify

# Specific test
mvn test -Dtest=ESTFrontendQuarkusTest
```

### Workflow 5: Build Native Image

```bash
# Inside container (requires more memory)
mvn package -Pnative

# Run native binary
./target/pki-est-quarkus-11.6.0-SNAPSHOT-runner
```

## Advanced Usage

### Run with Custom Ports

```bash
podman run -it --rm \
    -v $(pwd)/../..:/workspace/pki:Z \
    -p 9090:8080 \
    -p 9443:8443 \
    pki-est-quarkus-dev:latest
```

### Run as Detached Container

```bash
podman run -d \
    --name pki-est-dev \
    -v $(pwd)/../..:/workspace/pki:Z \
    -p 8080:8080 \
    -p 8443:8443 \
    pki-est-quarkus-dev:latest \
    tail -f /dev/null

# Execute commands
podman exec -it pki-est-dev bash

# Stop and remove
podman stop pki-est-dev
podman rm pki-est-dev
```

### Debug Maven Build

```bash
# Inside container
mvn clean package -X -e > build.log 2>&1
less build.log
```

### Access Multiple Shells

```bash
# Terminal 1: Start container
./podman-run.sh

# Terminal 2: Attach another shell
podman exec -it pki-est-quarkus bash
```

### Rebuild Parent PKI Only

```bash
# Inside container
cd /workspace/pki
./build.sh dist
```

## Troubleshooting

### Issue: "Error: cannot find Podman machine"

**macOS specific.** Initialize Podman machine:
```bash
podman machine init
podman machine start
podman machine list
```

### Issue: Permission denied on mounted volume

**SELinux context issue.** Use `:Z` flag (already in scripts):
```bash
-v $(pwd):/workspace/pki:Z
```

### Issue: Port already in use

Stop conflicting service or use different ports:
```bash
# Check what's using port 8080
sudo lsof -i :8080

# Or use different port
podman run ... -p 9090:8080 ...
```

### Issue: Container build fails

Clear cache and rebuild:
```bash
podman system prune -a
./podman-build.sh
```

### Issue: Out of memory during native build

Increase container memory:
```bash
# For Podman machine (macOS/Windows)
podman machine set --memory 8192

# For native Linux
# Already uses host resources
```

### Issue: Quarkus dev mode not accessible

Ensure binding to 0.0.0.0:
```bash
mvn quarkus:dev -Dquarkus.http.host=0.0.0.0
```

### Issue: Changes not reflected in container

Volume mount might not be working:
```bash
# Check mount
podman inspect pki-est-quarkus | grep -A5 Mounts

# Ensure :Z flag for SELinux
```

## Container Architecture

```
┌─────────────────────────────────────────────┐
│ Host Machine                                │
│                                             │
│  base/est-quarkus/                          │
│  ├── Containerfile          (builds image)  │
│  ├── podman-build.sh        (build script)  │
│  ├── podman-run.sh          (run script)    │
│  └── quarkus-dev.sh         (dev helper)    │
│                                             │
│  Ports exposed:                             │
│    8080  → Container :8080   (HTTP)         │
│    8443  → Container :8443   (HTTPS)        │
│    5005  → Container :5005   (Debug)        │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ Podman Container (Fedora 40)                │
│                                             │
│  /workspace/pki/  ← Volume mount (host src) │
│                                             │
│  Installed:                                 │
│    ✓ Java 17                                │
│    ✓ Maven 3.x                              │
│    ✓ JSS (from COPR)                        │
│    ✓ LDAP SDK (from COPR)                   │
│    ✓ Build tools (gcc, cmake, etc)          │
│                                             │
│  ~/.m2/repository/  (Maven cache)           │
│    └── org/dogtagpki/pki/  (built modules)  │
└─────────────────────────────────────────────┘
```

## Best Practices

### 1. Source Code Lives on Host
- Edit code on your host machine with your favorite IDE
- Container automatically picks up changes (live reload)
- Version control works normally on host

### 2. Build Artifacts in Container
- Maven cache (`~/.m2`) stays in container
- Compiled binaries in `target/` are visible on host

### 3. Use Named Volumes for Maven Cache (Optional)
```bash
# Create persistent Maven cache
podman volume create maven-cache

# Use it
podman run -v maven-cache:/root/.m2:Z ...
```

### 4. Clean Builds
```bash
# Inside container
mvn clean install

# Or rebuild parent PKI
cd /workspace/pki && ./build.sh dist
```

### 5. Keep Container Image Updated
```bash
# Periodically rebuild
./podman-build.sh
```

## Podman vs Docker Differences

If you're familiar with Docker:

| Docker | Podman | Notes |
|--------|--------|-------|
| `docker build` | `podman build` | Same syntax |
| `docker run` | `podman run` | Same options |
| `docker ps` | `podman ps` | Identical |
| Root daemon | Rootless | Podman doesn't need daemon |
| `docker-compose` | `podman-compose` | Install separately |
| `/var/run/docker.sock` | Not needed | No socket |

**Podman advantage**: Runs as regular user, no daemon, better security.

## Integration with IDEs

### VS Code

1. Install "Remote - Containers" extension
2. Or use terminal in VS Code:
   ```bash
   ./podman-run.sh
   ```

### IntelliJ IDEA

1. Use "Remote Development" feature
2. Or use external terminal for Podman

### Eclipse

Use terminal view to run container commands.

## Next Steps

1. **Start the environment**: `./podman-run.sh`
2. **Build the PoC**: `./quarkus-dev.sh`
3. **Access Dev UI**: http://localhost:8080/q/dev
4. **Read the docs**: [README.md](README.md), [MIGRATION-GUIDE.md](MIGRATION-GUIDE.md)
5. **Experiment**: Make changes, see live reload in action!

## Resources

- **Podman Documentation**: https://docs.podman.io/
- **Quarkus Container Guide**: https://quarkus.io/guides/podman
- **Containerfile Reference**: https://docs.podman.io/en/latest/markdown/podman-build.1.html
- **PoC Documentation**: [README.md](README.md)

---

**Questions or Issues?**

1. Check [BUILD.md](BUILD.md) for general build information
2. Review [TROUBLESHOOTING.md](#troubleshooting) above
3. Check Podman logs: `podman logs pki-est-quarkus`
