# Quick Reference Card - Apple Silicon

## 🎯 Your Situation
- **Hardware**: Apple Silicon (M1/M2/M3)
- **Limitation**: JSS/LDAP SDK only available for x86_64
- **Goal**: Understand/test Tomcat → Quarkus migration

## ⚡ Quick Commands

### Option 1: Review Environment (Fastest) ⭐
```bash
./podman-build.sh        # Build ARM64 container (~5 min)
./podman-run.sh          # Run and explore code
```
**Best for**: Learning patterns, reviewing architecture

### Option 2: x86 Emulation (Full Build)
```bash
./podman-build-x86.sh    # Build with QEMU (~45 min)
./podman-run-x86.sh      # Run emulated x86_64
```
**Best for**: Testing full functionality (slow)

### Option 3: Just Read (No Build)
```bash
cd /Users/czinda/git/pki/base
cat est-quarkus/README.md
cat est-quarkus/MIGRATION-GUIDE.md
diff -u est/src/main/java/org/dogtagpki/est/ESTEngine.java \
        est-quarkus/src/main/java/org/dogtagpki/est/quarkus/ESTEngineQuarkus.java
```
**Best for**: Quick overview

## 📊 Comparison Table

| Method | Build Time | Run Speed | Completeness | Difficulty |
|--------|-----------|-----------|--------------|------------|
| ARM64 Review | 5 min | N/A | 80% | Easy |
| x86 Emulation | 45 min | Slow (2-3x) | 100% | Easy |
| Cloud VM | 15 min | Fast | 100% | Medium |
| Just Read | 0 min | N/A | 60% | Easiest |

## 🗺️ File Guide

| File | Purpose |
|------|---------|
| `START-HERE.md` | This guide |
| `ARM64-README.md` | Complete ARM64 options |
| `QEMU-EMULATION-GUIDE.md` | Emulation details |
| `PODMAN.md` | Complete Podman docs |
| `README.md` | PoC architecture |
| `MIGRATION-GUIDE.md` | Migration patterns |

## 🚀 Recommended Workflow

**Day 1: Review (ARM64)**
```bash
./podman-build.sh && ./podman-run.sh
# Inside: explore code, read docs
```

**Day 2: Test (if needed)**
```bash
# If you need full build
./podman-build-x86.sh    # Start this, grab lunch
./podman-run-x86.sh
# Inside: ./quarkus-dev.sh
```

## 🔧 Setup QEMU Emulation

### First Time Setup
```bash
# Configure Podman machine
podman machine init --cpus 4 --memory 8192 --disk-size 60
podman machine start

# Verify
podman machine list
```

### Build x86_64 Image
```bash
./podman-build-x86.sh
# Coffee break: 30-45 minutes ☕
```

### Run Emulated Container
```bash
./podman-run-x86.sh

# Inside container
uname -m              # Verify: x86_64
./quarkus-dev.sh      # Start Quarkus
```

### Access from Browser
```
http://localhost:8080/q/dev
```

## ⚠️ Common Issues

### Podman Not Initialized
```bash
podman machine init --cpus 4 --memory 8192
podman machine start
```

### Build Timeout
```bash
# Increase timeout in podman-build-x86.sh
# Add: --timeout 7200
```

### Out of Memory
```bash
podman machine stop
podman machine set --memory 10240
podman machine start
```

### Very Slow
This is normal with QEMU. Options:
- Accept it (grab coffee during build)
- Use cloud VM instead
- Stick with ARM64 review

## 📚 Learn More

- **Emulation details**: `QEMU-EMULATION-GUIDE.md`
- **ARM64 options**: `ARM64-README.md`
- **Full Podman guide**: `PODMAN.md`
- **PoC architecture**: `README.md`

## 💡 Decision Helper

**Question**: Do you need to actually RUN the PoC?

**NO** → Use ARM64 review container
- Fastest
- Learn all the patterns
- 80% of value

**YES, for testing** → Use x86 emulation
- Full functionality
- Slower performance
- One-time verification

**YES, for development** → Use cloud VM
- Best performance
- Native x86_64
- Costs money

## ⚡ TL;DR

**For learning** (recommended):
```bash
./podman-build.sh && ./podman-run.sh
```

**For full testing**:
```bash
./podman-build-x86.sh && ./podman-run-x86.sh
```

**Most efficient**:
Read the docs, review the code, no build needed!

---

**Need help?** Open the relevant guide:
- ARM64 issues: `ARM64-README.md`
- Emulation: `QEMU-EMULATION-GUIDE.md`
- Podman: `PODMAN.md`
