MAKEFLAGS := --jobs=1

all: whatdoesitdo tests

whatdoesitdo:
	@# generate the README "What does it do?" section
	@./gen-readme.sh

# To decrease tests verbosity, comment out unneeded targets
tests: downloadffprefs checkdeprecated stats cleanup


downloadffprefs:
	@# download and sort all known preferences files from Firefox (mozilla-central) source
	@# specify wanted Firefox version/revision below (eg. "tip", "FIREFOX_AURORA_45_BASE", "9577ddeaafd85554c2a855f385a87472a089d5c0"). See https://hg.mozilla.org/mozilla-central/tags
	@SOURCEVERSION="tip"; \
	FIREFOX_SOURCE_PREFS=" \
	https://hg.mozilla.org/mozilla-central/raw-file/$$SOURCEVERSION/toolkit/components/telemetry/datareporting-prefs.js \
	https://hg.mozilla.org/mozilla-central/raw-file/$$SOURCEVERSION/toolkit/components/telemetry/healthreport-prefs.js \
	https://hg.mozilla.org/mozilla-central/raw-file/$$SOURCEVERSION/security/manager/ssl/security-prefs.js \
	https://hg.mozilla.org/mozilla-central/raw-file/$$SOURCEVERSION/modules/libpref/init/all.js \
	https://hg.mozilla.org/mozilla-central/raw-file/$$SOURCEVERSION/testing/profiles/prefs_general.js \
	https://hg.mozilla.org/mozilla-central/raw-file/$$SOURCEVERSION/layout/tools/reftest/reftest-preferences.js \
	https://hg.mozilla.org/mozilla-central/raw-file/$$SOURCEVERSION/js/src/tests/user.js"; \
	for SOURCEFILE in $$FIREFOX_SOURCE_PREFS; do wget -nv "$$SOURCEFILE" -O - ; done | egrep "(^pref|^user_pref)" | sort --unique >| sourceprefs.js

######################

checknotcovered:
	@# check for preferences present in firefox source but not covered by user.js
	@# configure ignored preferences in ignore.list
	@SOURCE_PREFS=$$(egrep '(^pref|^user_pref)' sourceprefs.js | awk -F'"' '{print $$2}'); \
	for SOURCE_PREF in $$SOURCE_PREFS; do \
	grep "\"$$SOURCE_PREF\"" user.js ignore.list >/dev/null || echo "Not covered by user.js : $$SOURCE_PREF"; \
	done | sort --unique

checkdeprecated:
	@# check for preferences in hardened user.js that are no longer present in firefox source
	@HARDENED_PREFS=$$(egrep "^user_pref" user.js | cut -d'"' -f2); \
	for HARDENED_PREF in $$HARDENED_PREFS; do \
	grep "\"$$HARDENED_PREF\"" sourceprefs.js  >/dev/null || echo "Deprecated : $$HARDENED_PREF"; \
	done | sort --unique

stats:
	@# count preferences number, various stats
	@echo "$$(egrep "^user_pref" user.js | wc -l | cut -f1) preferences in user.js"
	@echo "$$(wc -l sourceprefs.js | cut -d" " -f1) preferences in Firefox source"

cleanup: sourceprefs.js
	@# remove temporary files
	@# please comment this out when not needed, to minimize load on Mozilla servers
	@rm sourceprefs.js

authors:
	@# generate an AUTHORS file, ordered by number of commits
	@# TODO: add a .mailmap file to deduplicate authors with multiple email addresses
	@# to add extra authors/credits, git commit --allow-empty --author="A U Thor <author@example.com>"
	@git shortlog -sne | cut -f1 --complement >| AUTHORS
