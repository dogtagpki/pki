# Project Name - Dogtagpki

## Subsystem Installation using Ansible

### About

This ansible playbook is written to setup all the subsystems(CA, KRA, OCSP, TKS and TPS).
These playbooks can setup the environment based on the topology specified in the runtime.

### Requirements:

1. Pip should be installed.
2. Pip [requiremets.txt](../Installation/requirements.txt) should be installed
3. Make sure to check ansible version after installation.This can be quickly done using
ansible --version.
If this commands works, Your ansible is installed properly.

4. Before running the playbooks make sure machines that are going to communicate with each other they have passwordless communication working.
This can be easily done using:
                                  `ssh-copy-id root@<remote machine>`

This will ask you for one time password after which it will copy keys between machines.

### Verification Step
```
     ssh root@<remote host>
```
This should not prompt for password any more.

### Packages to Install `Only for RHEL users`

Configure repo that have below listed packages.It is mandatory to setup repo's
correctly  before triggering ansible playbooks for system installation.

```
Required Packages:

    - redhat-pki
    - redhat-pki-console-theme
    - redhat-pki-server-theme
    - pki-console
    - 389-ds-base
    - pki-ca
    - pki-kra
    - pki-ocsp
    - pki-tks
    - pki-tps
    - policycoreutils-python
    - expect
    - libselinux-python
```

### Usage:

For Setting up system with only pki packages installed, use `topology-00`
```
ansible-playbook -i /tmp/test/pki-tests/ci/ansible/host main.yml --extra-vars "topology=topology-00" -v
```

For Setting up Subsystems on different port, use `topology-02 `
```
ansible-playbook -i /tmp/test/pki-tests/ci/ansible/host main.yml --extra-vars "topology=topology-02" -v
```

For Setting up Subsystems on default and same port, use `topology-01`
```
ansible-playbook -i /tmp/test/pki-tests/ci/ansible/host main.yml --extra-vars "topology=topology-01" -v
```

where,

  -i INVENTORY, --inventory-file=INVENTORY
                        specify inventory host path
                        (default=/etc/ansible/hosts) or comma separated host
                        list.

## Examples of ansible-inventory

Inventory file consist of the roles and the ip-address.Tests will run for the roles and ip's that are mentioned.

```
[master]
10.1.2.3
10.2.3.4
```

### Sanity tests

Once playbook installation is complete, use below command and make certificates are returned.
```
        pki -p 20080 ca-cert-find
```
Incase, you are required to run any other topology let us say "topology-01" for shared instance, replace topology-02 with topology-01.


### Gathering Subsystems Facts

Gather configuration files, ports and other environment data from `/tmp/test_dir` on the system under test.


## References:

1. http://docs.ansible.com/ansible/intro.html
2. http://docs.ansible.com/ansible/intro_installation.html
