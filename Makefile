SHELL=/bin/bash

.PHONY: all
all: whatdoesitdo tests

.PHONY: whatdoesitdo
whatdoesitdo:
	@# generate the README "What does it do?" section
	@./gen-readme.sh

# To decrease tests verbosity, comment out unneeded targets
.PHONY: tests
tests: sourceprefs.js checkdeprecated stats acorn bash_syntax shellcheck

.PHONY: acorn
acorn:
	acorn --silent user.js

locked_user.js: user.js
	sed 's/^user_pref/lockPref/' $< >| $@

systemwide_user.js: user.js
	sed 's/^user_pref/pref/' $< >| $@

# https://github.com/mozilla/policy-templates/blob/master/README.md
policies.json:
	jq -n -M "{\"policies\": {\"OfferToSaveLogins\": false, \"DisableBuiltinPDFViewer\": true, \"DisablePocket\": true, \"DisableFormHistory\": true, \"SanitizeOnShutdown\": true, \"SearchBar\": \"separate\", \"DisableTelemetry\": true, \"Cookies\": {\"AcceptThirdParty\": \"never\", \"ExpireAtSessionEnd\": true}, \"EnableTrackingProtection\": {\"Value\": true}, \"PopupBlocking\": {\"Default\": true}, \"FlashPlugin\": {\"Default\": false}, \"DisableFirefoxStudies\": true}}" >| $@

.PHONY: bash_syntax
bash_syntax:
	$(foreach i,$(wildcard *.sh),bash -n $(i);)

.PHONY: shellcheck
shellcheck:
	shellcheck *.sh

# download and sort all known preferences files from Firefox (mozilla-central) source
# specify wanted Firefox version/revision below (eg. "tip", "FIREFOX_AURORA_45_BASE", "9577ddeaafd85554c2a855f385a87472a089d5c0"). See https://hg.mozilla.org/mozilla-central/tags
SOURCEVERSION=tip
FIREFOX_SOURCE_PREFS= \
	https://hg.mozilla.org/mozilla-central/raw-file/$(SOURCEVERSION)/toolkit/components/telemetry/datareporting-prefs.js \
	https://hg.mozilla.org/mozilla-central/raw-file/$(SOURCEVERSION)/toolkit/components/telemetry/healthreport-prefs.js \
	https://hg.mozilla.org/mozilla-central/raw-file/$(SOURCEVERSION)/security/manager/ssl/security-prefs.js \
	https://hg.mozilla.org/mozilla-central/raw-file/$(SOURCEVERSION)/modules/libpref/init/all.js \
	https://hg.mozilla.org/mozilla-central/raw-file/$(SOURCEVERSION)/testing/profiles/prefs_general.js \
	https://hg.mozilla.org/mozilla-central/raw-file/$(SOURCEVERSION)/layout/tools/reftest/reftest-preferences.js \
	https://hg.mozilla.org/mozilla-central/raw-file/$(SOURCEVERSION)/js/src/tests/user.js \
	https://hg.mozilla.org/mozilla-central/raw-file/$(SOURCEVERSION)/browser/app/profile/firefox.js \
	https://hg.mozilla.org/mozilla-central/raw-file/tip/devtools/client/preferences/debugger.js \
	https://hg.mozilla.org/mozilla-central/raw-file/tip/devtools/client/preferences/devtools.js \
	https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/branding/unofficial/pref/firefox-branding.js \
	https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/branding/official/pref/firefox-branding.js \
	https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/branding/nightly/pref/firefox-branding.js \
	https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/branding/aurora/pref/firefox-branding.js \
	https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/locales/en-US/firefox-l10n.js \
	https://hg.mozilla.org/mozilla-central/raw-file/tip/devtools/client/webide/webide-prefs.js \
	https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/app/profile/channel-prefs.js
sourceprefs.js:
	@for SOURCEFILE in $(FIREFOX_SOURCE_PREFS); do wget -nv "$$SOURCEFILE" -O - ; done | egrep "(^pref|^user_pref)" | sort --unique >| $@

TBBBRANCH=tor-browser-52.6.2esr-7.5-2
000-tor-browser.js:
	wget -nv "https://gitweb.torproject.org/tor-browser.git/plain/browser/app/profile/$@?h=$(TBBBRANCH)" -O $@

regex = ^\(user_\)\?pref/s/^.*pref("\([^"]\+\)",\s*\([^)]\+\).*$$
.PHONY: tbb-diff
tbb-diff: 000-tor-browser.js
	diff <(sed -n '/$(regex)/\1 = \2/p' user.js | sort) <(sed -n '/$(regex)/\1 = \2/p' $< | sort)

.PHONY: tbb-diff-2
tbb-diff-2: 000-tor-browser.js
	for setting in $$( comm -12 <(sed -n '/$(regex)/\1/p' user.js | sort) <(sed -n '/$(regex)/\1/p' $< | sort)); do diff <(grep "^\(user_\)\?pref(\"$${setting}\"" user.js | sed -n '/$(regex)/\1 = \2/p' | sort) <(grep "^\(user_\)\?pref(\"$${setting}\"" $< | sed -n '/$(regex)/\1 = \2/p' | sort); done

.PHONY: tbb-missing-from-user.js
tbb-missing-from-user.js: 000-tor-browser.js
	comm -13 <(sed -n '/$(regex)/\1/p' user.js | sort) <(sed -n '/$(regex)/\1/p' $< | sort)

######################

.PHONY: checknotcovered
checknotcovered: sourceprefs.js
	@# check for preferences present in firefox source but not covered by user.js
	@# configure ignored preferences in ignore.list
	@SOURCE_PREFS=$$(egrep '(^pref|^user_pref)' $< | awk -F'"' '{print $$2}'); \
	for SOURCE_PREF in $$SOURCE_PREFS; do \
	grep "\"$$SOURCE_PREF\"" user.js ignore.list >/dev/null || echo "Not covered by user.js : $$SOURCE_PREF"; \
	done | sort --unique

.PHONY: checkdeprecated
checkdeprecated: sourceprefs.js
	@# check for preferences in hardened user.js that are no longer present in firefox source
	@HARDENED_PREFS=$$(egrep "^user_pref" user.js | cut -d'"' -f2); \
	for HARDENED_PREF in $$HARDENED_PREFS; do \
	grep "\"$$HARDENED_PREF\"" $< >/dev/null || echo "Deprecated : $$HARDENED_PREF"; \
	done | sort --unique

.PHONY: stats
stats: sourceprefs.js
	@# count preferences number, various stats
	@echo "$$(egrep "^user_pref" user.js | wc -l | cut -f1) preferences in user.js"
	@echo "$$(wc -l $< | cut -d" " -f1) preferences in Firefox source"

.PHONY: clean
clean:
	@# remove temporary files
	@# please comment this out when not needed, to minimize load on Mozilla servers
	@rm -f sourceprefs.js AUTHORS

AUTHORS:
	@# generate an AUTHORS file, ordered by number of commits
	@# to add extra authors/credits, git commit --allow-empty --author="A U Thor <author@example.com>"
	@git shortlog -sne | cut -f1 --complement >| $@

.PHONY: toc
toc:
	@l2headers=$$(egrep "^## " README.md |cut -d" " -f1 --complement ); \
	echo "$$l2headers" | while read line; do \
	anchor=$$(echo "$$line" | tr '[:upper:]' '[:lower:]' | sed 's/ /-/g' | sed 's/\?//g'); \
	echo "* [$$line](#$$anchor)"; \
	done
