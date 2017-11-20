# Environment-Setup Instructions

## Installing pip

[pip] (https://pip.pypa.io/en/stable/installing/)  is needed for ansible & pytest installation.

## Installing Supporting Packages

Install the pip and run requirements.txt file 

```
pip install -r requirements.txt
```

## Installing CA, KRA, OCSP, TKS & TPS Subsystems

Refer [README.md] (installation/README.md)



## Running Pytest-Ansible test cases.

### Pre-requisite

1. Run Role user setup for setting up different users for different subsystem for setting up Admin, Agent, Revoked and Expired certificates.
    -- To-do
2. Refer [README.md] (pytest/README.md)