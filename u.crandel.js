// *******************************************************************
// Now settings from https://github.com/Crandel/home/blob/master/.mozilla/firefox/user.js
//
//
//
//
//
// Built in screenshots
user_pref("extensions.screenshots.disabled", true);
// Disable Firefox Accout
user_pref("identity.fxaccounts.enabled", false);

/******************************************************************* */
// Now settings from https://github.com/Crandel/home/blob/master/.mozilla/firefox/user.js
//
//
//
//
//

user_pref("accessibility.force_disabled", true);
// disable Firefox/Shield/Heartbeat
user_pref("app.normandy.enabled", false);
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("app.update.checkInstallTime", false);
user_pref("apz.allow_double_tap_zooming", false);
user_pref("apz.android.chrome_fling_physics.enabled", false);

user_pref("browser.discovery.enabled", false);
user_pref("browser.bookmarks.restore_default_bookmarks", false);
user_pref("browser.bookmarks.showMobileBookmarks", true);
user_pref("browser.ctrlTab.previews", true);
user_pref("browser.download.autohideButton", false);
user_pref("browser.download.panel.shown", true);
user_pref("browser.library.activity-stream.enabled", true);
user_pref(
  "browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons",
  false
);
user_pref(
  "browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features",
  false
);
user_pref("browser.newtabpage.activity-stream.feeds.places", true);
user_pref("browser.newtabpage.activity-stream.feeds.section.highlights", false);
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.filterAdult", false);
user_pref("browser.newtabpage.activity-stream.prerender", true);
user_pref(
  "browser.newtabpage.activity-stream.section.highlights.includePocket",
  false
);
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry.ping.endpoint", "");
user_pref("browser.newtabpage.activity-stream.tippyTop.service.endpoint", "");
user_pref("browser.newtabpage.activity-stream.topSitesRows", 3);
user_pref("browser.newtabpage.enhanced", true);
user_pref("browser.ping-centre.telemetry", true);

user_pref("browser.privatebrowsing.searchUI", false);
user_pref("browser.safebrowsing.blockedURIs.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.block_dangerous", false);
user_pref("browser.safebrowsing.downloads.remote.block_dangerous_host", false);
user_pref(
  "browser.safebrowsing.downloads.remote.block_potentially_unwanted",
  false
);
user_pref("browser.safebrowsing.downloads.remote.block_uncommon", false);
user_pref("browser.safebrowsing.downloads.remote.enabled", false);
user_pref("browser.safebrowsing.enabled", false);
// Safe Browsing offers phishing protection and malware checks, however it may send user information
// (e.g. URL, file hashes, etc.) to third parties like Google.
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);

user_pref("browser.safebrowsing.provider.google.advisoryURL", "");
user_pref("browser.safebrowsing.provider.google.gethashURL", "");
user_pref("browser.safebrowsing.provider.google.lists", "");
user_pref("browser.safebrowsing.provider.google.pver", "");
user_pref("browser.safebrowsing.provider.google.reportMalwareMistakeURL", "");
user_pref("browser.safebrowsing.provider.google.reportPhishMistakeURL", "");
user_pref("browser.safebrowsing.provider.google.reportURL", "");
user_pref("browser.safebrowsing.provider.google.updateURL", "");
user_pref("browser.safebrowsing.provider.google4.advisoryName", "");
user_pref("browser.safebrowsing.provider.google4.advisoryURL", "");
user_pref("browser.safebrowsing.provider.google4.dataSharingURL", "");
user_pref("browser.safebrowsing.provider.google4.gethashURL", "");
user_pref("browser.safebrowsing.provider.google4.lastupdatetime", "");
user_pref("browser.safebrowsing.provider.google4.lists", "");
user_pref("browser.safebrowsing.provider.google4.nextupdatetime", "");
user_pref("browser.safebrowsing.provider.google4.pver", "");
user_pref("browser.safebrowsing.provider.google4.reportMalwareMistakeURL", "");
user_pref("browser.safebrowsing.provider.google4.reportPhishMistakeURL", "");
user_pref("browser.safebrowsing.provider.google4.reportURL", "");
user_pref("browser.safebrowsing.provider.google4.updateURL", "");
user_pref("browser.safebrowsing.provider.mozilla.gethashURL", "");
user_pref("browser.safebrowsing.provider.mozilla.lists", "");
user_pref("browser.safebrowsing.provider.mozilla.pver", "");
user_pref("browser.safebrowsing.provider.mozilla.updateURL", "");

user_pref("browser.search.countryCode", "US");
user_pref("browser.search.geoSpecificDefaults", false);
user_pref("browser.search.geoSpecificDefaults.url", "");
user_pref("browser.search.geoip.url", "");
user_pref("browser.search.hiddenOneOffs", "Bing,Amazon.com,Twitter");
user_pref("browser.search.region", "US");
user_pref("browser.search.update", "false");
user_pref("browser.send_pings", false);
user_pref("browser.sessionstore.interval", 1800000);
user_pref("browser.slowStartup.notificationDisabled", true);
user_pref("browser.startup.page", 3);

user_pref("browser.tabs.drawInTitlebar", true);
user_pref("browser.tabs.loadInBackground", false);
user_pref("browser.tabs.remote.autostart", true);
user_pref("browser.tabs.tabMinWidth", 30);
user_pref("browser.tabs.warnOnClose", false);
user_pref("browser.touchmode.auto", false);
user_pref("browser.uitour.enabled", false);
user_pref("browser.urlbar.clickSelectsAll", true);
user_pref("browser.urlbar.maxRichResults", 15);
user_pref("browser.urlbar.trimURLs", false);
user_pref("datareporting.healthreport.uploadEnabled", true);
user_pref("datareporting.policy.dataSubmissionEnabled", true);
user_pref("datareporting.policy.firstRunURL", "");

user_pref("device.sensors.enabled", false);
user_pref("device.sensors.motion.enabled", false);
user_pref("device.sensors.orientation.enabled", false);
user_pref("devtools.aboutdebugging.showSystemAddons", true);
user_pref("devtools.onboarding.telemetry.logged", true);
user_pref("devtools.theme", "dark");
user_pref("devtools.toolbox.splitconsoleEnabled", false);
user_pref("dom.enable_performance_observer", false);
user_pref("dom.event.clipboardevents.enabled", false);
user_pref("dom.gamepad.enabled", false);
user_pref("dom.gamepad.extensions.enabled", false);
user_pref("dom.push.enabled", false);
user_pref("dom.vibrator.enabled", false);

user_pref("experiments.activeExperiment", true);
user_pref("experiments.enabled", true);
user_pref("experiments.supported", false);

user_pref("extensions.fxmonitor.enabled", false);
user_pref("extensions.getAddons.cache.enabled", false);
user_pref("extensions.getAddons.showPane", false);
user_pref("extensions.htmlaboutaddons.discover.enabled", false);
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);
user_pref("extensions.pocket.enabled", false);
user_pref("extensions.ui.dictionary.hidden", false);
user_pref("extensions.ui.experiment.hidden", false);
user_pref("extensions.ui.locale.hidden", false);
user_pref("extensions.webextensions.remote", false);
// blacklist for webextensions
user_pref(
  "extensions.webextensions.restrictedDomains",
  "accounts-static.cdn.mozilla.net,accounts.firefox.com,oauth.accounts.firefox.com,profile.accounts.firefox.com,sync.services.mozilla.com"
);
user_pref("extensions.webextensions.userScripts.enabled", true);
user_pref("findbar.highlightAll", true);
// I disable custom font for a while

// user_pref("font.internaluseonly.changed", true);
// user_pref("font.minimum-size.x-western", 10);
// user_pref("font.name.monospace.x-western", "Hack");
// user_pref("font.name.sans-serif.x-western", "Hack");
// user_pref("font.name.serif.x-western", "Hack");

user_pref("full-screen-api.warning.timeout", 0);
user_pref("general.smoothScroll.durationToIntervalRatio", 1000);
user_pref("general.smoothScroll.lines.durationMaxMS", 100);
user_pref("general.smoothScroll.lines.durationMinMS", 100);
user_pref("general.smoothScroll.mouseWheel.durationMaxMS", 150);
user_pref("general.smoothScroll.mouseWheel.durationMinMS", 50);
user_pref("general.smoothScroll.msdPhysics.enabled", true);
user_pref("general.smoothScroll.other", false);
user_pref("general.smoothScroll.pixels", false);
user_pref("general.smoothScroll.scrollbars.durationMaxMS", 100);
user_pref("general.smoothScroll.scrollbars.durationMinMS", 100);
user_pref(
  "general.useragent.override.skype.com",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
);
user_pref("general.warnOnAboutConfig", false);
user_pref("geo.wifi.uri", "");
user_pref("gestures.enable_single_finger_input", false);
user_pref("gfx.font_rendering.cleartype_params.rendering_mode", 5);
user_pref("gfx.gfx.webrender.all.qualified", true);
user_pref("gfx.use_text_smoothing_setting", true);
user_pref("gfx.webrender.all", true);
user_pref("gfx.webrender.enabled", true);

user_pref("gfx.webrender.highlight-painted-layers", false);
user_pref("gfx.work-around-driver-bugs", false);
user_pref("intl.accept_languages", "en-us,en,uk,ru");
user_pref("intl.locale.requested", "en-US");
user_pref("javascript.options.shared_memory", true);

// user_pref("layers.acceleration.force-enabled", true);
user_pref("layers.amd-switchable-gfx.enabled", false);
user_pref("layers.geometry.d3d11.enabled", false);


user_pref("layout.css.devPixelsPerPx", "1.25");
user_pref("layout.css.osx-font-smoothing.enabled", true);
user_pref("layout.word_select.stop_at_punctuation", true);


user_pref(
  "lightweightThemes.selectedThemeID",
  "firefox-compact-dark@mozilla.org"
);
user_pref("media.autoplay.allow-muted", false);
user_pref("media.autoplay.default", 1);
user_pref("media.autoplay.enabled", false);
user_pref("media.av1.enabled", true);
user_pref("media.gpu-process-decoder", true);
user_pref("media.videocontrols.picture-in-picture.enabled", true);
user_pref("media.webspeech.synth.enabled", false);
user_pref("mousewheel.min_line_scroll_amount", 36);



user_pref("network.allow-experiments", true);
user_pref("network.cookie.prefsMigrated", true);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.http.speculative-parallel-limit", 0);
user_pref("network.predictor.enabled", false);
user_pref("network.prefetch-next", false);
user_pref("network.security.esni.enabled", true);
user_pref("network.stricttransportsecurity.preloadlist", true);
user_pref("network.tcp.tcp_fastopen_enable", true);
user_pref("network.trr.mode", 2);
user_pref("network.trr.uri", "https://mozilla.cloudflare-dns.com/dns-query");
user_pref("network.warnOnAboutNetworking", false);
user_pref("nglayout.initialpaint.delay", 150);
user_pref("pdfjs.enableWebGL", true);

user_pref("permissions.default.desktop-notification", 2);
user_pref("permissions.default.geo", 2);
user_pref("privacy.donottrackheader.enabled", true);
// for jira
user_pref("privacy.firstparty.isolate", false);
user_pref("privacy.resistFingerprinting", true);
user_pref(
  "privacy.resistFingerprinting.autoDeclineNoUserInputCanvasPrompts",
  false
);
// enable webextensions on mozilla websites
user_pref("privacy.resistFingerprinting.block_mozAddonManager", true);
user_pref("privacy.userContext.enabled", true);
user_pref("privacy.userContext.longPressBehavior", 2);
user_pref("privacy.userContext.ui.enabled", true);
user_pref("reader.color_scheme", "dark");
user_pref("reader.content_width", 12);
user_pref("security.ssl.errorReporting.automatic", true);
// exclude sync of addons status enabled/disabled
user_pref("services.sync.addons.ignoreUserEnabledChanges", true);
user_pref("services.sync.prefs.sync.browser.newtabpage.enabled", false);
user_pref(
  "services.sync.prefs.sync.browser.newtabpage.activity-stream.section.highlights.includePocket",
  false
);

user_pref("toolkit.identity.enabled", false);
user_pref("toolkit.cosmeticAnimations.enabled", false);
user_pref("toolkit.telemetry.archive.enabled", true);
user_pref("toolkit.telemetry.bhrPing.enabled", true);
user_pref("toolkit.telemetry.coverage.opt-out", true);
user_pref("toolkit.telemetry.enabled", true);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", true);
user_pref("toolkit.telemetry.hybridContent.enabled", true);
user_pref("toolkit.telemetry.newProfilePing.enabled", true);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", true);
user_pref("toolkit.telemetry.shutdownPingSender.enabled", true);
user_pref("toolkit.telemetry.unified", true);
user_pref("toolkit.telemetry.updatePing.enabled", true);

user_pref("webgl.force-enabled", true);
user_pref("webgl.msaa-force", true);
user_pref("widget.chrome.allow-gtk-dark-theme", true);
user_pref("widget.content.allow-gtk-dark-theme", true);
// user_pref("widget.content.gtk-theme-override", "Adwaita:light");
