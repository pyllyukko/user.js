SHELL=/bin/bash

all: whatdoesitdo tests

##### INSTALLATION METHODS #####

.PHONY: locked_user.js # generate a locked configuration file
locked_user.js: user.js
	sed 's/^user_pref/lockPref/' $< >| $@

.PHONY: systemwide_user.js # generate a system-wide configuration file
systemwide_user.js: user.js
	sed 's/user_pref(/pref(/' $< >| $@

.PHONY: debian_locked.js # # generate a locked, system-wide configuration file
debian_locked.js: user.js
	sed 's/^user_pref(\("[^"]\+"\),\s\+\([^)]\+\));\(\s*\/\/.*\)\?$$/pref(\1, \2, locked);/' $< >| $@

.PHONY: policies.json # generate policy file (https://github.com/mozilla/policy-templates/blob/master/README.md)
policies.json:
	jq -n -M "{\"policies\": {\"OfferToSaveLogins\": false, \"DisableBuiltinPDFViewer\": true, \"DisablePocket\": true, \"DisableFormHistory\": true, \"SanitizeOnShutdown\": true, \"SearchBar\": \"separate\", \"DisableTelemetry\": true, \"Cookies\": {\"AcceptThirdParty\": \"never\", \"ExpireAtSessionEnd\": true}, \"EnableTrackingProtection\": {\"Value\": true}, \"PopupBlocking\": {\"Default\": true}, \"FlashPlugin\": {\"Default\": false}, \"DisableFirefoxStudies\": true}}" >| $@


##### TESTS #####

.PHONY: tests # run all tests
tests: sourceprefs.js checkdeprecated stats acorn bash_syntax shellcheck

.PHONY: acorn # validate user.js syntax
acorn:
	acorn --silent user.js

.PHONY: bash_syntax # check syntax of all bash scripts
bash_syntax:
	$(foreach i,$(wildcard *.sh),bash -n $(i);)

.PHONY: shellcheck # check/lint shell scripts
shellcheck:
	shellcheck *.sh


##### DIFF GENERATION/COMPARISONS WIT UPSTREAM/TOR BROWSER #####

TBBBRANCH=tor-browser-68.8.0esr-9.5-1
.PHONY: 000-tor-browser.js # download Tor Browser custom configuration reference
000-tor-browser.js:
	wget -nv "https://gitweb.torproject.org/tor-browser.git/plain/browser/app/profile/firefox.js?h=$(TBBBRANCH)" -O $@

PREF_REGEX = ^\(user_\)\?pref/s/^.*pref("\([^"]\+\)",\s*\([^)]\+\).*$$
.PHONY: tbb-diff # differences between values from this user.js and tor browser's values
tbb-diff: 000-tor-browser.js
	diff <(sed -n '/$(PREF_REGEX)/\1 = \2/p' user.js | sort) <(sed -n '/$(PREF_REGEX)/\1 = \2/p' $< | sort)

.PHONY: tbb-diff-2 # differences between values from this user.js and tor browser's values (alternate method)
tbb-diff-2: 000-tor-browser.js
	for setting in $$( comm -12 <(sed -n '/$(PREF_REGEX)/\1/p' user.js | sort) <(sed -n '/$(PREF_REGEX)/\1/p' $< | sort)); do diff <(grep "^\(user_\)\?pref(\"$${setting}\"" user.js | sed -n '/$(regex)/\1 = \2/p' | sort) <(grep "^\(user_\)\?pref(\"$${setting}\"" $< | sed -n '/$(regex)/\1 = \2/p' | sort); done

.PHONY: tbb-missing-from-user.js # preferences that are present in tor browser's defaults, but not in this user.js
tbb-missing-from-user.js: 000-tor-browser.js
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
.PHONY: sourceprefs.js # download and sort all known preferences files from Firefox (mozilla-central) source
sourceprefs.js:
	@for SOURCEFILE in $(FIREFOX_SOURCE_PREFS); do wget -nv "$$SOURCEFILE" -O - ; done | egrep "(^pref|^user_pref)" | sort --unique >| $@

.PHONY: upstream-duplicates # preferences with common values with default Firefox configuration
upstream-duplicates: sourceprefs.js
	@sed 's/^pref(/user_pref(/' sourceprefs.js | sed -E "s/[[:space:]]+/ /g" | sort > sourceprefs_sorted.js
	@grep "^user_pref" user.js | sed -E "s/[[:space:]]+/ /g" | sort > userjs_sorted.js
	@comm -1 -2  sourceprefs_sorted.js userjs_sorted.js

.PHONY: upstream-missing-from-user.js # preferences present in firefox source but not covered by user.js
upstream-missing-from-user.js: sourceprefs.js
    # configure ignored preferences in ignore.list
	@SOURCE_PREFS=$$(egrep '(^pref|^user_pref)' $< | awk -F'"' '{print $$2}'); \
	for SOURCE_PREF in $$SOURCE_PREFS; do \
	grep "\"$$SOURCE_PREF\"" user.js ignore.list >/dev/null || echo "Not covered by user.js : $$SOURCE_PREF"; \
	done | sort --unique

.PHONY: checkdeprecated # preferences in hardened user.js that are no longer present in firefox source
upstream-deprecated: sourceprefs.js
	@HARDENED_PREFS=$$(egrep "^user_pref" user.js | cut -d'"' -f2); \
	for HARDENED_PREF in $$HARDENED_PREFS; do \
	grep "\"$$HARDENED_PREF\"" $< >/dev/null || echo "Deprecated : $$HARDENED_PREF"; \
	done | sort --unique

.PHONY: stats # count preferences number, various stats
stats: sourceprefs.js
	@echo "$$(egrep "^user_pref" user.js | wc -l | cut -f1) preferences in user.js"
	@echo "$$(wc -l $< | cut -d" " -f1) preferences in Firefox source"


##### DOCUMENTATION GENERATION #####

.PHONY: whatdoesitdo # generate the README "What does it do?" section
whatdoesitdo:
	@./gen-readme.sh

.PHONY: clean # generate/update the README "What does it do?" section
clean:
	@rm -f sourceprefs.js sourceprefs_sorted.js userjs_sorted.js 000-tor-browser.js debian_locked.js

.PHONY: toc # generate the README table of contents
toc:
	@l2headers=$$(egrep "^## " README.md |cut -d" " -f1 --complement ); \
	echo "$$l2headers" | while read line; do \
	anchor=$$(echo "$$line" | tr '[:upper:]' '[:lower:]' | sed 's/ /-/g' | sed 's/\?//g'); \
	echo "* [$$line](#$$anchor)"; \
	done

.PHONY: help # generate list of targets with descriptions
help:
	@grep '^.PHONY: .* #' Makefile | sed 's/\.PHONY: \(.*\) # \(.*\)/\1	\2/' | expand -t20
