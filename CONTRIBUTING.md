
GUIDELINE
---------

Contributions guideline:

* Keep the code simple
* Don't add extra dependency: dependencies have costs that is better to avoid. 
* compatibility: keep the code compatible with previous versions of GHC, and base.
* Don't drop older SSL / TLS features (even if insecure) without proper discussion.
* Limit the change of API if necessary. it's usually better to create new API than
  change current one.
* Notable exception to previous rule: security fix have priority to other considerations.

MAINTAINERS
-----------

* Don't commit code directly to master, apart from targeted fixes (e.g. documentation improvements, build scripts, etc).
* PRs: make sure they pass compilations and runtime tests before merging
* Let someone else merge your own PR, or give other maintainers a chance to review
* separate meaningful code from syntax changes

SUPPORT
-------

* Need to support all the GHC versions listed in the .travis file.
* Operating systems: Windows, OSX and unix (Linux, BSD)
