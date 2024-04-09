#!/bin/bash

echo "Automated script testing whether our presented container escape vulnerabilities can be exploited" 

vuln_bool=0

# Create a directory to mount the cgroup
test_dir=/tmp/test
mkdir -p "$test_dir" && echo "Directory created successfully" || { echo "ERROR: failed to create test directory at $test_dir"; exit 1; }

# Check for Docker socket access
if [ -e /var/run/docker.sock ]; then
    echo "/!\ This container is vulnerable to DinD / DooD attack. To mitigate, do not allow access to the docker socket inside a container. Consider using tools like Kaniko or Buildah for building Docker images inside a container."
    vuln_bool=1
fi

# Check for cgroup mount capability via CAP_SYS_ADMIN is possible
if mount -t cgroup -o memory cgroup $test_dir >/dev/null 2>&1 ; then
    # Test if release_agent is writable
    if test -w $test_dir/release_agent ; then
        echo "/!\ The container can escape by manipulating the release_agent file because it has the CAP_SYS_ADMIN and doesn't run with AppArmor or SELinux. To mitigate, restrict the Capability, and use AppArmor and SELinux."
        umount $test_dir
        vuln_bool=1
    fi
    umount $test_dir
fi

# Check for CVE-2022-0492 exploitation capability
if unshare -UrmC bash -c 'cap=$(grep CapEff /proc/$$/status | cut -f2); if capsh --decode=$cap | grep -q cap_sys_admin; then echo "Vulnerable to CVE-2022-0492"; else echo "Not vulnerable"; fi' >/dev/null 2>&1; then
    echo "/!\ This container can abuse user namespace to escape and potentially gain CAP_SYS_ADMIN (related to CVE-2022-0492)."
    vuln_bool=1
fi

# Cleaning
rm -rf $test_dir

# Cannot escape via either method
if [ $vuln_bool -eq 0 ]; then
    echo "Attempt to attack failed. This container appears to be properly secured against such vulnerabilities"
fi
