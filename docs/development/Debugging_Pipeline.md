# Debugging QE Pipeline Failures

When QE pipeline fails, the console output for the `Setup tmate session` task
will display a ssh address such as:

    ssh <REDACTED>@nyc1.tmate.io

This can be used to get an active session on the MacOS host the pipelines
run on. This creates a tmux session as `root` on the MacOS host. From
here, switch to the `runner` user:

    # sudo su runner
    $ cd

In `$HOME/work/pki/pki/` is the cloned GitHub repo, plus Vagrant home. There
are two VMs currently provisioned in this pipeline:

 - `controller` at IP address `192.168.33.10`, which runs Ansible
 - `master` at IP address `192.168.33.20`, which runs PKI (and is
   the target of Anisble playbooks.

You can SSH into each using Vagrant's ssh keys

    $ ssh -i $HOME/work/pki/pki/.vagrant/machines/controller/virtualbox/private_key root@192.168.33.10
    $ ssh -i $HOME/work/pki/pki/.vagrant/machines/master/virtualbox/private_key root@192.168.133.20

Sometimes, `vagrant` might have problems, such as when a VM crashes. You can
check the status of these VMs via:

    $ cd $HOME/work/pki/pki && vagrant status controller
    $ cd $HOME/work/pki/pki && vagrant status master

From here, debugging should be the same as if the instance was in a regular
VM.
