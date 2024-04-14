#!/bin/bash


echo "[*] Starting vulnerability check..."


# Detection of the CVE-2022-0492 vulnerability

# Check kernel version 
echo "[*] Checking kernel version..."
kernel_version=$(uname -r)
echo "Kernel version: $kernel_version"

# Check the active cgroup version
echo "[*] Determining active cgroup version..."
if mount | grep -q "cgroup2"; then
    echo "[+] Using cgroup v2. This system is not vulnerable to CVE-2022-0492."
    exit 0
elif mount | grep -q "cgroup "; then
    echo "[-] Using cgroup v1, potentially vulnerable."
else
    echo "[-] Unable to determine the cgroup version or cgroup not used."
    exit 1
fi

# Check if AppArmor or SELinux is active
echo "[*] Checking for security modules..."
if command -v aa-status && aa-status >/dev/null; then
    echo "[+] AppArmor is active."
elif command -v sestatus && sestatus | grep -q "enabled"; then
    echo "[+] SELinux is active."
else
    echo "[-] Neither AppArmor nor SELinux is active."
fi

# Check if Seccomp is active and in what mode
seccomp_status=$(grep Seccomp /proc/self/status | awk '{print $2}')
case $seccomp_status in
    0) echo "[-] Seccomp is not active." ;;
    1) echo "[+] Seccomp is active in strict mode." ;;
    2) echo "[+] Seccomp is active in filter mode." ;;
    *) echo "[-] Unknown Seccomp status." ;;
esac

# Setup test directory
test_dir=/tmp/.cve-2022-0492-test
echo "[*] Setting up test environment..."
if ! mkdir -p $test_dir ; then
    echo "ERROR: Failed to create test directory at $test_dir"
    exit 1
else
    echo "Test directory created successfully."
fi

vuln_bool=0

# Test for potential escape methods
echo "[*] Testing for possible escape methods..."
# Testing escape via CAP_SYS_ADMIN -> if mount succeeds, CAP_SYS_ADMIN=1
# Mount a memory cgroup and check if the release_agent file is writable
# This tests if the container can escape using CAP_SYS_ADMIN capabilities

if mount -t cgroup -o memory cgroup $test_dir >/dev/null 2>&1; then
    if test -w $test_dir/release_agent; then
        echo "[!] WARNING: Container may escape due to CAP_SYS_ADMIN without AppArmor/SELinux enforcement."
        vuln_bool=1
    fi
    # Remove the test directory ($test_dir) after mount test
    umount $test_dir >/dev/null 2>&1
fi

# Testing escape via user namespaces for each cgroup subsystem
echo "[*] Testing escape via user namespaces for each cgroup subsystem..."
while IFS=: read -r _ subsys _; do
    # For each cgroup subsystem, attempt to create a new user namespace and mount the cgroup subsystem
    if unshare -UrmC --propagation=unchanged bash -c "mount -t cgroup -o $subsys cgroup $test_dir >/dev/null 2>&1"; then
        # Check if the release_agent file is writable
        if [ -w $test_dir/release_agent ]; then
            echo "[!] WARNING: Container may abuse user namespaces to escape in $subsys subsystem."
            vuln_bool=1
        fi
        # Unmount the cgroup subsystem after testing
        umount $test_dir >/dev/null 2>&1
    fi
done <<< "$(awk -F':' '/:cgroup:/ { print $2 }' /proc/$$/cgroup)"

if [ $vuln_bool -eq 1 ]; then
    echo "/!\ This container is at risk of CVE-2022-0492 vulnerability. To mitigate, you might want to update your kernel, mrigrate to cgroupe v2, configure SELinux, AppArmor, and Seccomp."
fi

# Detection of the DinD/DooD vulnerability

# Check for Docker socket access
if [ -e /var/run/docker.sock ]; then
    vuln_bool=1
    echo "/!\ This container is vulnerable to DinD/DooD attack. To mitigate, do not allow access to the docker socket inside a container. Consider using tools like Kaniko or Buildah for building Docker images inside a container."
    echo "/!\ Ensure your system maintains strict permissions by avoiding the use of --privileged and --cap-add SYS_ADMIN unless absolutely necessary."
fi

# Cleaning
rm -rf $test_dir

# Final verdict
if [ $vuln_bool -eq 0 ]; then
    echo "[+] System appears secure against CVE-2022-0492 exploit methods."
    echo "[+] System appears secure against DinD/DooD attack."
else
    echo "/!\ System potentially vulnerable, please check the configurations of your container."
fi
