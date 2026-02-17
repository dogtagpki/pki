# 🚀 START HERE - EST Quarkus PoC

## You're on Apple Silicon (ARM64 Mac)

The build script detected your architecture and will guide you through the appropriate setup.

## Quick Decision Tree

```
Are you on Apple Silicon (M1/M2/M3)?
│
├─ YES → You have 3 options:
│   │
│   ├─ Option 1: Review Environment (Recommended) ⭐
│   │   Time: 5 minutes
│   │   Value: 80% of PoC benefit
│   │   → Run: ./podman-build.sh
│   │   → Read: ARM64-README.md
│   │
│   ├─ Option 2: Platform Emulation (QEMU)
│   │   Time: 45 minutes build + slower runtime
│   │   Value: 100% but 2-3x slower
│   │   → Run: ./podman-build-x86.sh
│   │   → Read: QEMU-EMULATION-GUIDE.md
│   │
│   └─ Option 3: Cloud x86_64 VM
│       Time: 20 minutes
│       Value: 100% with full performance
│       → Read: ARM64-README.md (Option 3)
│
└─ NO → Full build available!
    → Run: ./podman-build.sh
    → Read: PODMAN.md
```

## Recommended Path for ARM64 (You)

### Step 1: Build Review Container (5 minutes)

```bash
./podman-build.sh
# Press 'y' when prompted
```

### Step 2: Run and Explore

```bash
./podman-run.sh
```

### Step 3: Inside Container - Review Code

```bash
# Compare Tomcat vs Quarkus
cd /workspace/pki/base

# View directory structure
tree -L 2 est/
tree -L 2 est-quarkus/

# Compare lifecycle management
diff -u \
  est/src/main/java/org/dogtagpki/est/ESTWebListener.java \
  est-quarkus/src/main/java/org/dogtagpki/est/quarkus/ESTEngineQuarkus.java

# Compare REST endpoints
diff -u \
  est/src/main/java/org/dogtagpki/est/ESTFrontend.java \
  est-quarkus/src/main/java/org/dogtagpki/est/quarkus/ESTFrontendQuarkus.java

# Read documentation
cat est-quarkus/README.md | less
cat est-quarkus/MIGRATION-GUIDE.md | less
```

## What You Can Learn (Without Full Build)

### ✅ Available on ARM64

1. **Architecture Understanding**
   - How Quarkus replaces Tomcat ServletContextListener with CDI
   - How authentication changes from Realm/Valve to IdentityProvider
   - How configuration moves from web.xml to application.yaml

2. **Code Comparison**
   - Side-by-side diff of Tomcat vs Quarkus implementations
   - See namespace changes (javax → jakarta)
   - Study dependency injection patterns

3. **Migration Patterns**
   - Learn step-by-step migration guide
   - Understand common pitfalls
   - See real-world examples

4. **Documentation**
   - Complete PoC README
   - Migration guide
   - Build instructions
   - Troubleshooting

### ❌ Not Available on ARM64

1. **Full Build**
   - Cannot install JSS (x86_64 only)
   - Cannot install LDAP SDK (x86_64 only)
   - Cannot build parent PKI modules

2. **Runtime Testing**
   - Cannot run with real EST backend
   - Cannot test certificate operations
   - Cannot validate full integration

**BUT:** 80% of PoC value comes from architecture/patterns, which you CAN learn!

## Files Overview

```
base/est-quarkus/
├── START-HERE.md              ← You are here
├── ARM64-README.md            ← Detailed ARM64 guide
├── QUICKSTART.md              ← All usage options
├── PODMAN.md                  ← Complete Podman docs
├── README.md                  ← PoC architecture
├── MIGRATION-GUIDE.md         ← Step-by-step migration
├── BUILD.md                   ← Build requirements
├── Containerfile              ← x86_64 full build
├── Containerfile.arm64        ← ARM64 review environment
├── podman-build.sh            ← Build script (auto-detects arch)
├── podman-run.sh              ← Run script
└── quarkus-dev.sh             ← Quarkus dev mode helper
```

## Next Steps

### For Review/Learning (Recommended for ARM64)

1. Read [ARM64-README.md](ARM64-README.md) - ARM64-specific guide
2. Run `./podman-build.sh` - Build review container
3. Run `./podman-run.sh` - Start container
4. Explore code and documentation

### For Full Build (If Needed)

1. Read [ARM64-README.md](ARM64-README.md) Option 2 or 3
2. Choose: Platform emulation OR Cloud VM
3. Follow detailed instructions

### For x86_64 Linux Users

1. Read [PODMAN.md](PODMAN.md)
2. Run `./podman-build.sh`
3. Run `./podman-run.sh`
4. Run `./quarkus-dev.sh`

## Quick Command Reference

```bash
# Build (auto-detects architecture)
./podman-build.sh

# Run
./podman-run.sh

# Inside container: explore
cd /workspace/pki/base
ls -la est/ est-quarkus/

# Inside container: read docs
less est-quarkus/README.md

# Inside container: compare code
diff -u est/src/main/java/org/dogtagpki/est/ESTEngine.java \
        est-quarkus/src/main/java/org/dogtagpki/est/quarkus/ESTEngineQuarkus.java
```

## Need Help?

1. **ARM64 issues**: [ARM64-README.md](ARM64-README.md)
2. **Podman issues**: [PODMAN.md](PODMAN.md)
3. **Build issues**: [BUILD.md](BUILD.md)
4. **General questions**: [QUICKSTART.md](QUICKSTART.md)

## Summary

**You're on ARM64 (Apple Silicon):**
- ✅ Review environment available (recommended)
- ✅ Learn migration patterns and architecture
- ✅ Study code comparisons
- ❌ Full build requires x86_64 or emulation

**Value proposition:**
80% of PoC value = Understanding patterns (available on ARM64)
20% of PoC value = Running code (requires x86_64)

**Ready to start?**
```bash
./podman-build.sh
```

Press 'y' when prompted, then explore the code!

---

**TL;DR for ARM64 users:**
Run `./podman-build.sh`, press 'y', then `./podman-run.sh` to start reviewing the code. Read [ARM64-README.md](ARM64-README.md) for details.
