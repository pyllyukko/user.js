Contributing
============

Guidelines to contributing to this project.

General
-------

* Write descriptive commit messages
* Add proper references (links) to both the user.js file and the commit message
  * References need to be from trusted sources (e.g. Mozilla bug tracker, or other Mozilla documentation). Or it needs to be somehow verifiable.
* One issue/feature set in one commit, so it's easy to track the changes in the log and process the pull requests
  * Preferably in separate pull requests. This way it's also easier to discuss about different settings/features.
* Cosmetic changes (wording, typos, etc.) in their own pull requests

Removing settings
-----------------

Removing obsolete settings has raised some discussion in this project. Usually, when Firefox gets rid of some setting/feature, it doesn't hurt even though we have it in the user.js file. It's just not being used and clutters up the user.js.

When suggesting to remove some setting, please consider the following:

* Just because some setting doesn't show up in ```about:config``` by default, does not mean that Firefox wouldn't utilize that setting somehow
* Provide a reference to e.g. Mozilla bug tracker, that describes the removal of this particular setting/feature
