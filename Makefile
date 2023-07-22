SHELL=/bin/bash

.PHONY: all
all: whatdoesitdo tests

.PHONY: FORCE
FORCE:

##### INSTALLATION METHODS #####

locked_user.js: user.js FORCE # generate a locked configuration file
	sed 's/^user_pref/lockPref/' $< >| $@

systemwide_user.js: user.js FORCE # generate a system-wide configuration file
	sed 's/user_pref(/pref(/' $< >| $@

debian_locked.js: user.js FORCE # generate a locked, system-wide configuration file
	sed 's/^user_pref(\("[^"]\+"\),\s\+\([^)]\+\));\(\s*\/\/.*\)\?$$/pref(\1, \2, locked);/' $< >| $@


##### TESTS #####
# Requirements: node-acorn shellcheck

.PHONY: tests
tests: test-acorn test-shellcheck # run all tests

.PHONY: test-acorn
test-acorn: # validate user.js syntax
	acorn --silent user.js

.PHONY: test-shellcheck
test-shellcheck: # check/lint shell scripts
	shellcheck *.sh


##### DIFF GENERATION/COMPARISONS WIT UPSTREAM/TOR BROWSER #####

TBBBRANCH=tor-browser-68.8.0esr-9.5-1
000-tor-browser.js: FORCE # download Tor Browser custom configuration reference
	wget -nv "https://gitweb.torproject.org/tor-browser.git/plain/browser/app/profile/firefox.js?h=$(TBBBRANCH)" -O $@

PREF_REGEX = ^\(user_\)\?pref/s/^.*pref("\([^"]\+\)",\s*\([^)]\+\).*$$
.PHONY: diff-tbb
diff-tbb: 000-tor-browser.js # differences between values from this user.js and tor browser's values
	diff <(sed -n '/$(PREF_REGEX)/\1 = \2/p' user.js | sort) <(sed -n '/$(PREF_REGEX)/\1 = \2/p' $< | sort)

.PHONY: diff-tbb-2
diff-tbb-2: 000-tor-browser.js # differences between values from this user.js and tor browser's values (alternate method)
	for setting in $$( comm -12 <(sed -n '/$(PREF_REGEX)/\1/p' user.js | sort) <(sed -n '/$(PREF_REGEX)/\1/p' $< | sort)); do diff <(grep "^\(user_\)\?pref(\"$${setting}\"" user.js | sed -n '/$(regex)/\1 = \2/p' | sort) <(grep "^\(user_\)\?pref(\"$${setting}\"" $< | sed -n '/$(regex)/\1 = \2/p' | sort); done

.PHONY: diff-tbb-missing-from-user.js
diff-tbb-missing-from-user.js: 000-tor-browser.js # preferences that are present in tor browser's defaults, but not in this user.js
	comm -13 <(sed -n '/$(PREF_REGEX)/\1/p' user.js | sort) <(sed -n '/$(PREF_REGEX)/\1/p' $< | sort)

# specify wanted Firefox version/revision below (eg. "tip", "FIREFOX_AURORA_45_BASE", "9577ddeaafd85554c2a855f385a87472a089d5c0"). See https://hg.mozilla.org/mozilla-central/tags
SOURCEVERSION=tip
FIREFOX_SOURCE_PREFS= \
	https://hg.mozilla.org/mozilla-central/raw-file/$(SOURCEVERSION)/modules/libpref/init/all.js \
	https://hg.mozilla.org/mozilla-central/raw-file/$(SOURCEVERSION)/testing/profiles/common/user.js \
	https://hg.mozilla.org/mozilla-central/raw-file/$(SOURCEVERSION)/testing/profiles/reftest/user.js \
	https://hg.mozilla.org/mozilla-central/raw-file/$(SOURCEVERSION)/js/src/tests/user.js \
	https://hg.mozilla.org/mozilla-central/raw-file/$(SOURCEVERSION)/browser/app/profile/firefox.js \
	https://hg.mozilla.org/mozilla-central/raw-file/tip/devtools/client/preferences/debugger.js \
	https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/branding/unofficial/pref/firefox-branding.js \
	https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/branding/official/pref/firefox-branding.js \
	https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/branding/nightly/pref/firefox-branding.js \
	https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/branding/aurora/pref/firefox-branding.js \
	https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/locales/en-US/firefox-l10n.js \
	https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/app/profile/channel-prefs.js
.PHONY: diff-sourceprefs.js
diff-sourceprefs.js: # download and sort all known preferences files from Firefox (mozilla-central) source
	@for SOURCEFILE in $(FIREFOX_SOURCE_PREFS); do wget -nv "$$SOURCEFILE" -O - ; done | egrep "(^pref|^user_pref)" | sort --unique >| sourceprefs.js

.PHONY: diff-upstream-duplicates
diff-upstream-duplicates: diff-sourceprefs.js # preferences with common values with default Firefox configuration
	@sed 's/^pref(/user_pref(/' sourceprefs.js | sed -E "s/[[:space:]]+/ /g" | sort > sourceprefs_sorted.js
	@grep "^user_pref" user.js | sed -E "s/[[:space:]]+/ /g" | sort > userjs_sorted.js
	@comm -1 -2  sourceprefs_sorted.js userjs_sorted.js

.PHONY: diff-upstream-missing-from-user.js
diff-upstream-missing-from-user.js: diff-sourceprefs.js # preferences present in firefox source but not covered by user.js
    # configure ignored preferences in ignore.list
	@SOURCE_PREFS=$$(egrep '(^pref|^user_pref)' $< | awk -F'"' '{print $$2}'); \
	for SOURCE_PREF in $$SOURCE_PREFS; do \
	grep "\"$$SOURCE_PREF\"" user.js ignore.list >/dev/null || echo "Not covered by user.js : $$SOURCE_PREF"; \
	done | sort --unique

.PHONY: diff-upstream-deprecated
diff-upstream-deprecated: diff-sourceprefs.js # preferences in hardened user.js that are no longer present in firefox source
	@HARDENED_PREFS=$$(egrep "^user_pref" user.js | cut -d'"' -f2); \
	for HARDENED_PREF in $$HARDENED_PREFS; do \
	grep "\"$$HARDENED_PREF\"" $< >/dev/null || echo "Deprecated : $$HARDENED_PREF"; \
	done | sort --unique

.PHONY: diff-stats
diff-stats: diff-sourceprefs.js # count preferences number, various stats
	@echo "$$(egrep "^user_pref" user.js | wc -l | cut -f1) preferences in user.js"
	@echo "$$(wc -l $< | cut -d" " -f1) preferences in Firefox source"


##### MISC #####

.PHONY: clean
clean: # clean automatically generated files/build/test artifacts
	@rm -f sourceprefs.js sourceprefs_sorted.js userjs_sorted.js 000-tor-browser.js debian_locked.js systemwide_user.js

##### DOCUMENTATION GENERATION #####

.PHONY: doc-whatdoesitdo
doc-whatdoesitdo: # generate the README "What does it do?" section
	@./gen-readme.sh

.PHONY: doc-toc
doc-toc: # generate the README table of contents
	@l2headers=$$(egrep "^## " README.md |cut -d" " -f1 --complement ); \
	echo "$$l2headers" | while read line; do \
	anchor=$$(echo "$$line" | tr '[:upper:]' '[:lower:]' | sed 's/ /-/g' | sed 's/\?//g'); \
	echo "* [$$line](#$$anchor)"; \
	done

.PHONY: help
help: # generate list of targets with descriptions
	@sed -n '/^[a-z0-9]/s/^\(.\+\):.*\s\+#\s\+\(.\+\)$$/\1\t\2/p' $(MAKEFILE_LIST) | expand -t20
