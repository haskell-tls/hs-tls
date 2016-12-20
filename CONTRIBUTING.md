
GUIDELINE
---------

Contributions guideline:

* Keep the code simple
* Don't add extra dependency: dependencies have costs that is better to avoid. 
* compatibility: keep the code compatible with previous versions of GHC, and base.

MAINTAINERS
-----------

* Don't commit code directly to master, apart from targeted fixes (e.g. documentation improvements, build scripts, etc).
* PRs: make sure they pass compilations and runtime tests before merging
* Let someone else merge your own PR, or give other maintainers a chance to review
* separate meaningful code from syntax changes

SUPPORT
-------

Need to support all the GHC versions listed in the .travis file.
