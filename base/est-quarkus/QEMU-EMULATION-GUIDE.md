# QEMU x86_64 Emulation on Apple Silicon

## Overview

Podman on macOS uses QEMU behind the scenes to run Linux containers. We can leverage this to emulate x86_64 architecture and build the full PKI stack.

## Method 1: Podman with Platform Flag (Easiest)

Podman automatically uses QEMU for cross-platform emulation.

### Step 1: Configure Podman Machine

```bash
# Stop existing machine (if any)
podman machine stop
podman machine rm podman-machine-default

# Create new machine with more resources for emulation
podman machine init \
    --cpus 4 \
    --memory 8192 \
    --disk-size 60 \
    --rootful

# Start the machine
podman machine start

# Verify it's running
podman machine list
```

### Step 2: Build with Platform Emulation

```bash
cd base/est-quarkus

# Build x86_64 image with QEMU emulation
# This will be SLOW (~30-45 minutes)
podman build \
    --platform linux/amd64 \
    -f Containerfile \
    -t pki-est-quarkus-dev:x86 \
    ../../

# You'll see this during build:
# WARNING: image platform (linux/amd64) does not match the expected platform (linux/arm64)
# This is normal - it means QEMU emulation is active
```

### Step 3: Run the Emulated Container

```bash
# Run with platform specification
podman run -it --rm \
    --platform linux/amd64 \
    -v $(pwd)/../..:/workspace/pki:Z \
    -p 8080:8080 \
    -p 8443:8443 \
    -p 5005:5005 \
    pki-est-quarkus-dev:x86

# Inside container (x86_64 emulated)
uname -m
# Shows: x86_64

./quarkus-dev.sh
```

## Method 2: Automated Script with Emulation

I'll create a script that does this for you:

```bash
cd base/est-quarkus

# Use the emulation script
./podman-build-x86.sh
```

### Expected Performance

**Build Time Comparison:**
- Native ARM64 build: ~5 minutes
- Emulated x86_64 build: ~30-45 minutes (6-9x slower)
- Native x86_64 build: ~10-15 minutes

**Runtime Performance:**
- ~2-3x slower than native
- Acceptable for testing/development
- Not recommended for production

## Method 3: QEMU User Mode (Advanced)

For direct QEMU usage without containers:

### Step 1: Install QEMU

```bash
# Install QEMU with x86_64 support
brew install qemu

# Verify installation
qemu-system-x86_64 --version
```

### Step 2: Download x86_64 Linux VM

```bash
# Download Fedora Cloud image
curl -LO https://download.fedoraproject.org/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2

# Create a larger disk
qemu-img create -f qcow2 -F qcow2 -b Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2 fedora-pki.qcow2 50G
```

### Step 3: Run QEMU VM

```bash
# Start VM with SSH forwarding
qemu-system-x86_64 \
    -M q35 \
    -m 8192 \
    -smp 4 \
    -cpu max \
    -accel hvf \
    -drive file=fedora-pki.qcow2,if=virtio \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::2222-:22,hostfwd=tcp::8080-:8080,hostfwd=tcp::8443-:8443 \
    -nographic

# Access via SSH
ssh -p 2222 fedora@localhost
```

### Step 4: Inside VM - Build PKI

```bash
# Inside QEMU VM
sudo dnf install podman git

# Clone and build
git clone https://github.com/dogtagpki/pki
cd pki/base/est-quarkus
./podman-build.sh
./podman-run.sh
```

## Method 4: UTM (GUI Alternative)

UTM is a user-friendly QEMU frontend for macOS.

### Step 1: Install UTM

```bash
brew install --cask utm

# Or download from: https://mac.getutm.app/
```

### Step 2: Create Fedora VM

1. Open UTM
2. Create New Virtual Machine
3. Choose "Virtualize" (faster with Apple Hypervisor for x86_64)
4. Select Linux
5. Download Fedora 40 x86_64 ISO
6. Configure:
   - Memory: 8GB
   - CPUs: 4 cores
   - Disk: 50GB
7. Install Fedora
8. Configure SSH and port forwarding

### Step 3: Use VM for Development

```bash
# SSH into UTM VM
ssh your-vm-ip

# Build PKI normally
cd ~/pki/base/est-quarkus
./podman-build.sh
./podman-run.sh
```

## Comparison of Methods

| Method | Setup Time | Build Time | Complexity | Best For |
|--------|-----------|------------|------------|----------|
| **Podman --platform** | 5 min | 30-45 min | Low | Quick testing |
| **QEMU VM** | 30 min | 10-15 min | High | Frequent use |
| **UTM GUI** | 20 min | 10-15 min | Medium | GUI preference |
| **Cloud VM** | 10 min | 10-15 min | Low | Best performance |

## Recommended Approach

### For One-Time Build/Test:
✅ **Use Podman --platform** (Method 1)
- Simplest setup
- Automated
- No VM management

### For Regular Development:
✅ **Use UTM or Cloud VM**
- Better performance
- Native x86_64 speed
- Full Linux environment

### Just for Learning:
✅ **Use ARM64 review container**
- Fastest
- 80% of value
- No emulation needed

## Performance Tips

### 1. Increase Podman Machine Resources

```bash
# More CPU cores = faster builds
podman machine set --cpus 6 --memory 10240
podman machine stop && podman machine start
```

### 2. Use Build Cache

```bash
# Subsequent builds will be faster
podman build --platform linux/amd64 --layers ...
```

### 3. Build Incrementally

```bash
# Build parent PKI separately
podman run --platform linux/amd64 -it --rm \
    -v $(pwd)/../..:/workspace:Z \
    registry.fedoraproject.org/fedora:40 \
    bash -c "cd /workspace && ./build.sh dist"

# Then build PoC
podman build --platform linux/amd64 ...
```

### 4. Parallel Builds

```bash
# Limit Maven threads to avoid overwhelming QEMU
mvn -T 1C ...  # 1 thread per CPU core
```

## Troubleshooting

### Issue: Build Times Out

Increase timeouts:
```bash
podman build --platform linux/amd64 \
    --timeout 7200 \
    ...
```

### Issue: Out of Memory

```bash
# Increase Podman machine memory
podman machine stop
podman machine set --memory 12288
podman machine start
```

### Issue: Very Slow Performance

This is normal with QEMU emulation. Options:
1. Accept slower performance
2. Switch to cloud VM (native x86_64)
3. Use ARM64 review container for learning

### Issue: "exec format error"

Forgot `--platform` flag:
```bash
# Wrong
podman run -it pki-est-quarkus-dev:x86

# Correct
podman run --platform linux/amd64 -it pki-est-quarkus-dev:x86
```

## Detailed Step-by-Step Example

### Complete Workflow with Emulation

```bash
# 1. Configure Podman
podman machine stop
podman machine rm podman-machine-default
podman machine init --cpus 4 --memory 8192 --disk-size 60
podman machine start

# 2. Navigate to PoC
cd /Users/czinda/git/pki/base/est-quarkus

# 3. Build with emulation (grab coffee - 30-45 min)
echo "Starting emulated build at $(date)"
time podman build \
    --platform linux/amd64 \
    -f Containerfile \
    -t pki-est-quarkus-dev:x86 \
    ../../
echo "Build finished at $(date)"

# 4. Run the container
podman run -it --rm \
    --platform linux/amd64 \
    --name pki-est-dev \
    -v $(pwd)/../..:/workspace/pki:Z \
    -p 8080:8080 \
    -p 8443:8443 \
    pki-est-quarkus-dev:x86

# 5. Inside container - verify x86_64
uname -m  # Should show: x86_64
lscpu     # Should show: x86_64

# 6. Start Quarkus
./quarkus-dev.sh

# 7. Access from host browser
# http://localhost:8080/q/dev
```

## Monitoring Emulation Performance

```bash
# Check QEMU processes
ps aux | grep qemu

# Monitor Podman machine resource usage
podman machine ssh
top
```

## When to Use Emulation

### ✅ Use QEMU Emulation When:
- You need to test full PKI functionality
- You want to validate actual EST operations
- You need JSS/LDAP SDK integration
- You're testing for production deployment

### ❌ Don't Use QEMU Emulation When:
- Just reviewing code/architecture
- Learning migration patterns
- Time-sensitive development
- Limited by slow performance

## Alternative: Pre-built Images

If available, use pre-built x86_64 images:

```bash
# Pull from registry (if published)
podman pull --platform linux/amd64 quay.io/dogtagpki/est-quarkus:latest

# Run directly
podman run --platform linux/amd64 -it \
    -v $(pwd)/../..:/workspace:Z \
    quay.io/dogtagpki/est-quarkus:latest
```

## Summary

**Fastest setup:** Podman with `--platform linux/amd64`
**Best performance:** UTM VM or Cloud VM
**Simplest:** ARM64 review container (no emulation)

**My recommendation for you:**
1. Start with ARM64 review container to learn patterns
2. If you need full build, use Podman emulation once
3. For regular development, set up UTM VM or use cloud

**Ready to start?**

```bash
# Quick emulation build
cd base/est-quarkus
podman machine init --cpus 4 --memory 8192
podman machine start
podman build --platform linux/amd64 -f Containerfile -t pki-est-quarkus-dev:x86 ../../
```

---

See [ARM64-README.md](ARM64-README.md) for comparison of all options.
