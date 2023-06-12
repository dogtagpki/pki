EST
===

EST tests for CI

Requirements
------------
The only requirement is the `community.docker` module

Role Variables
--------------

**DS** related variables: 

- `ds_container`: name of the container running directory server (_ds_);
- `ds_image`: image for the directory server container (_quay.io/389ds/dirsrv_);
- `ds_hostname`: hostname for directory server container (_ds.example.com_);
- `ds_password`: direcotry server password (_Secret.123_).

**CA** related variables:

- `pki_container`: name of the container running the CA and EST subsystem(_pki_);
- `pki_image`: image for CA deplyment container (*pki_runner*);
- `pki_hostname`: hostname for the CA (_pki.example.com_).

**libest** client variables:

- `client_container`: name of the container running the client (_client_);
- `client_image`: image for the client container (_quay.io/dogtagpki/libest_);
- `client_hostname`: hostname for the client (_client.example.com_)



Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: servers
      roles:
         - est

License
-------

GPL-2-and-later

Author Information
------------------

Marco Fargetta (mfargett@redhat.com)
