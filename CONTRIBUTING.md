# Contributing to Dogtag PKI

Dogtag PKI is a complex product and we'd appreciate the invaluable assistance of the community.
Therefore we would love any input you would consent to share! Any and all contributions, both big and small, will be considered but most importantly appreciated. In that spirit to follow is a brief list of major categories of contributions that would be most useful to us at Dogtag PKI.

**Examples of valuable contributions:**

- Reporting defects with the product (Bugs)
- Contributing to active code pull requests with comments and suggestions
- Actually submitting important fixes for consideration to be included in the product
- Proposing new features to the product. This one is crucial as fresh ideas can invigorate the effort
- Going through the process required to become an official maintainer of the code

## We Develop with Github

We use github to host code and feature requests, as well as accept pull requests. We use [Pagure](https://pagure.io/dogtagpki/issues) to track issues (we will be moving to github issues soon).

## Submitting Code Changes

Pull requests are the best way to propose changes to the codebase (we use [Github Flow](https://guides.github.com/introduction/flow/index.html)). We actively welcome your pull requests:

1. Fork the repo and create your branch from master.
2. If you've changed or added APIs, update the documentation. (In [docs/](docs/) , [docs/man/](docs/manuals/) or [Dogtag wiki](https://www.dogtagpki.org))
3. Ensure the whole CI suite passes. This includes building, linting and testing a simple PKI deployment across **current stable Fedora releases**. Since [FreeIPA](https://github.com/freeipa/freeipa) depends on Dogtag PKI, we also include certificate related smoke tests in our CI suite.
4. Issue that Pull Request! Ensure to follow [PR guidelines](#Pull-Request-Description) to write the description.
5. Once a submission is approved and merged, we will of course make every effort to assure that proper credit for the contribution is reflected in the commit log.

See also [PKI specific github cheatsheet](https://www.dogtagpki.org/wiki/GitHub_Pull_Request)

## Report Issues

We use Pagure issues to track public bugs. Report a bug by [opening a new issue](https://pagure.io/dogtagpki/new_issue); it's that easy!

**Note:** *We will be moving to Github Issues soon. All existing Pagure issues will be migrated.*

### Bug Reports

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code/steps if you can
  - Please post sample log file segments if useful and appropriate. Most usually the **debug log** file is most appropriate
- What you expected would happen
- What actually happens

**Notes:** possibly include theories to explain the behaviour, or steps you tried that didn't work or any other information you think that’s valuable that will help our team to provide a fix soon.

People ***love*** thorough bug reports. [This is a good example](https://pagure.io/dogtagpki/issue/3194) of a thorough bug report.

## Documentation

We have 3 different documentation categories:

1. [User/Admin guides](docs/), which describe how to use the features
2. [Man pages](docs/manuals/), which include the manuals for configuration files and CLI commands
3. [Wiki pages](https://www.dogtagpki.org/wiki/PKI_Main_Page), which include the design, technical and non-product specific information

Wiki pages are the best place to start learning about the product. If you have any issues or find any bugs in our documentation please feel free to open a PR or [contact us](#Contact).

## Style Guidelines

### Git Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the subject to less than 50 characters
- Separate subject from body with a blank line
- Reference issues and pull requests liberally after the first line
- Wrap the commit message body at 72 characters
- Use the body to explain what and why vs. how

### Pull Request Description

While issuing a Pull Request, Github by default, autofills the PR description from all your commit messages. Though this suffices most times, you may have to manually clean it.

- Ensure the description contains a detailed description
- Include test procedure, if applicable
- Provide a link to the upstream issue, if any
- Provide additional information, which you think reviewers must be aware of before reviewing your PR

[This is a good example](https://github.com/dogtagpki/pki/pull/471) of issuing a PR.

### Python Coding Style

We lint our Python code against both *PyLint* and *Flake8*; we run PyLint against our own [pylintrc](tools/pylintrc) file.

## Contact

You can reach the Dogtag PKI team over the **#dogtag-pki** channel on freenode.net. Note that you need to be a [registered user](https://freenode.net/kb/answer/registration) to message on this channel. You can also send an email to pki-users@redhat.com.

See also [Contact Us](https://www.dogtagpki.org/wiki/Contact_Us)

## License

All contributions must be submitted under the license specified in the [LICENSE](LICENSE) document.
