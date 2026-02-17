# Apple Silicon (ARM64) Users - Quick Guide

## The Situation

You're on an Apple Silicon Mac (M1/M2/M3), and the full PKI stack cannot be built because:

❌ **JSS** (Java Security Services) - Only available for x86_64
❌ **LDAP SDK** - Only available for x86_64
❌ **COPR @pki/master** - No ARM64 builds available

## Your Options

### Option 1: Review Environment (Fastest) ⭐

**What you CAN do:**
- ✅ Review all PoC source code
- ✅ Compare Tomcat vs Quarkus side-by-side
- ✅ Study migration patterns and architecture
- ✅ Read comprehensive documentation
- ✅ Learn Quarkus development patterns

**Steps:**
```bash
cd base/est-quarkus

# Build ARM64 review container
./podman-build.sh
# (Press 'y' when prompted)

# Run the container
./podman-run.sh

# Inside container: browse code
cd /workspace/pki/base
tree -L 3 est/          # Original Tomcat code
tree -L 3 est-quarkus/  # New Quarkus code

# Compare implementations
diff -u est/src/main/java/org/dogtagpki/est/ESTEngine.java \
        est-quarkus/src/main/java/org/dogtagpki/est/quarkus/ESTEngineQuarkus.java

# Read documentation
cat est-quarkus/README.md
cat est-quarkus/MIGRATION-GUIDE.md
```

**What you CANNOT do:**
- ❌ Build full PKI with JSS/LDAP SDK
- ❌ Run with real certificate backends
- ❌ Test actual EST protocol operations

**Value:** ~80% of PoC value comes from understanding patterns, not running code!

### Option 2: Platform Emulation (Slow but Complete)

Build and run x86_64 container with QEMU emulation:

```bash
# Initialize Podman with larger VM
podman machine stop
podman machine rm
podman machine init --cpus 4 --memory 8192 --disk-size 50
podman machine start

# Build for x86_64 (slow - ~30-45 minutes)
podman build --platform linux/amd64 \
    -f base/est-quarkus/Containerfile \
    -t pki-est-quarkus-dev:x86 \
    ../../

# Run with emulation
podman run --platform linux/amd64 -it --rm \
    -v $(pwd)/../..:/workspace/pki:Z \
    -p 8080:8080 -p 8443:8443 \
    pki-est-quarkus-dev:x86
```

**Pros:**
- ✅ Full build capability
- ✅ Can run complete PoC

**Cons:**
- ❌ Very slow (QEMU emulation overhead)
- ❌ High resource usage
- ❌ Longer build times

### Option 3: Cloud x86_64 VM (Production-Like)

Use a free/cheap x86_64 cloud instance:

**AWS EC2:**
```bash
# Launch t3.medium (2 vCPU, 4GB RAM)
# Choose Amazon Linux 2023 or Fedora

# SSH in and clone repo
ssh ec2-user@<instance-ip>
git clone https://github.com/dogtagpki/pki
cd pki/base/est-quarkus

# Run normally
./podman-build.sh
./podman-run.sh
```

**GCP Compute Engine:**
```bash
# Create e2-medium instance with Fedora
# Same steps as AWS
```

**Oracle Cloud (Free Tier):**
- Ampere A1 (ARM64) - Won't work for full build
- VM.Standard.E2.1.Micro (x86_64) - Will work, limited resources

**Pros:**
- ✅ Native x86_64 performance
- ✅ Full build capability
- ✅ Can use free tiers

**Cons:**
- ❌ Requires cloud account
- ❌ Network latency for development

### Option 4: Multi-Architecture Build (Advanced)

Build both architectures:

```bash
# Build ARM64 review environment
podman build -f Containerfile.arm64 \
    -t pki-est-quarkus-dev:arm64 ../../

# Build x86_64 with emulation for full features
podman build --platform linux/amd64 \
    -f Containerfile \
    -t pki-est-quarkus-dev:x86 ../../

# Use ARM64 for quick code review
podman run -it pki-est-quarkus-dev:arm64

# Use x86_64 for full testing (slower)
podman run --platform linux/amd64 -it pki-est-quarkus-dev:x86
```

## Recommended Workflow for Apple Silicon Users

**Phase 1: Understanding (ARM64 container)**
1. Build ARM64 review container
2. Review source code and documentation
3. Study migration patterns
4. Understand architecture changes

**Phase 2: Validation (if needed)**
- Use Option 2 (emulation) or Option 3 (cloud VM)
- Build and test full PoC
- Validate actual functionality

## Quick Commands

**Build ARM64 review environment:**
```bash
./podman-build.sh
# Press 'y' when prompted
```

**Run and review code:**
```bash
./podman-run.sh

# Inside container
cd /workspace/pki/base
diff -u est/src/main/java/org/dogtagpki/est/ESTFrontend.java \
        est-quarkus/src/main/java/org/dogtagpki/est/quarkus/ESTFrontendQuarkus.java
```

**Read docs inside container:**
```bash
less est-quarkus/README.md
less est-quarkus/MIGRATION-GUIDE.md
less est-quarkus/PODMAN.md
```

## What About Docker?

Same issue - JSS/LDAP SDK aren't available for ARM64:

```bash
# Docker also needs platform emulation
docker build --platform linux/amd64 ...
```

Podman and Docker have the same limitation on Apple Silicon.

## Why No ARM64 Support?

JSS (Java Security Services) and LDAP SDK are:
- Part of Red Hat ecosystem
- Built for x86_64 Linux servers
- Not commonly deployed on ARM64
- Would require significant porting effort

The Quarkus PoC itself has no ARM64 issues - it's the dependencies that are x86_64-only.

## Summary

**Best approach for Apple Silicon:**
1. ✅ Use ARM64 review environment (Option 1)
2. ✅ Get 80% of value from code review
3. ✅ If you need full build, use cloud VM (Option 3)
4. ❌ Avoid emulation (Option 2) unless necessary - very slow

**Bottom line:** The PoC's value is in demonstrating migration patterns, which you can fully appreciate on ARM64!

## Questions?

See [PODMAN.md](PODMAN.md) for complete Podman documentation.
