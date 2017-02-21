/******************************************************************************
 * user.js                                                                    *
 * https://github.com/pyllyukko/user.js                                       *
 ******************************************************************************/

 /*****************************************************************************
 * Avoid hardware based fingerprintings                                       *
 * Canvas/Font's/Plugins                                                      *
 ******************************************************************************/
// https://wiki.mozilla.org/Platform/GFX/HardwareAcceleration
// https://www.macromedia.com/support/documentation/en/flashplayer/help/help01.html
// https://github.com/dillbyrne/random-agent-spoofer/issues/74
 user_pref("gfx.direct2d.disabled",				true);
 user_pref("layers.acceleration.disabled",			true);


/******************************************************************************
 * HTML5 / APIs / DOM                                                         *
 *                                                                            *
 ******************************************************************************/

// Make sure the User Timing API does not provide a new high resolution timestamp
// https://trac.torproject.org/projects/tor/ticket/16336
user_pref("dom.enable_user_timing",				false);

// disable Location-Aware Browsing
// https://www.mozilla.org/en-US/firefox/geolocation/
user_pref("geo.enabled",					false);

// Disable dom.mozTCPSocket.enabled (raw TCP socket support)
// https://trac.torproject.org/projects/tor/ticket/18863
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-97/
// https://developer.mozilla.org/docs/Mozilla/B2G_OS/API/TCPSocket
user_pref("dom.mozTCPSocket.enabled",				false);

// http://kb.mozillazine.org/Dom.storage.enabled
// https://html.spec.whatwg.org/multipage/webstorage.html
// you can also see this with Panopticlick's "DOM localStorage"
//user_pref("dom.storage.enabled",		false);

// Whether JS can get information about the network/browser connection
// Network Information API provides general information about the system's connection type (WiFi, cellular, etc.)
// https://developer.mozilla.org/en-US/docs/Web/API/Network_Information_API
// https://wicg.github.io/netinfo/#privacy-considerations
// https://bugzilla.mozilla.org/show_bug.cgi?id=960426
user_pref("dom.netinfo.enabled",				false);

// Disable Web Audio API
// https://bugzil.la/1288359
user_pref("dom.webaudio.enabled",				false);

// Don't reveal your internal IP
// Check the settings with: http://net.ipcalf.com/
// https://wiki.mozilla.org/Media/WebRTC/Privacy
user_pref("media.peerconnection.ice.default_address_only",	true); // Firefox < 51
user_pref("media.peerconnection.ice.no_host",			true); // Firefox >= 51
// Disable WebRTC entirely
user_pref("media.peerconnection.enabled",			false);

// getUserMedia
// https://wiki.mozilla.org/Media/getUserMedia
// https://developer.mozilla.org/en-US/docs/Web/API/Navigator
user_pref("media.navigator.enabled",				false);
// https://developer.mozilla.org/en-US/docs/Web/API/BatteryManager
user_pref("dom.battery.enabled",				false);
// https://wiki.mozilla.org/WebAPI/Security/WebTelephony
user_pref("dom.telephony.enabled",				false);
// https://developer.mozilla.org/en-US/docs/Web/API/navigator.sendBeacon
user_pref("beacon.enabled",					false);
// https://developer.mozilla.org/en-US/docs/Mozilla/Preferences/Preference_reference/dom.event.clipboardevents.enabled
user_pref("dom.event.clipboardevents.enabled",			false);
// https://wiki.mozilla.org/Security/Reviews/Firefox/NavigationTimingAPI
user_pref("dom.enable_performance",				false);

// Speech recognition
// https://dvcs.w3.org/hg/speech-api/raw-file/tip/speechapi.html
// https://wiki.mozilla.org/HTML5_Speech_API
user_pref("media.webspeech.recognition.enable",			false);

// Disable getUserMedia screen sharing
// https://mozilla.github.io/webrtc-landing/gum_test.html
user_pref("media.getusermedia.screensharing.enabled",		false);

// Disable sensor API
// https://wiki.mozilla.org/Sensor_API
user_pref("device.sensors.enabled",				false);

// http://kb.mozillazine.org/Browser.send_pings
user_pref("browser.send_pings",					false);
// this shouldn't have any effect, since we block pings altogether, but we'll set it anyway.
// http://kb.mozillazine.org/Browser.send_pings.require_same_host
user_pref("browser.send_pings.require_same_host",		true);

// https://developer.mozilla.org/en-US/docs/IndexedDB
// https://wiki.mozilla.org/Security/Reviews/Firefox4/IndexedDB_Security_Review
// TODO: find out why html5test still reports this as available
// NOTE: this is enabled for now, as disabling this seems to break some plugins.
//       see: http://forums.mozillazine.org/viewtopic.php?p=13842047#p13842047
//user_pref("dom.indexedDB.enabled",		true);

// TODO: "Access Your Location" "Maintain Offline Storage" "Show Notifications"

// Disable gamepad input
// https://www.w3.org/TR/gamepad/
user_pref("dom.gamepad.enabled",				false);

// Disable virtual reality devices
// https://developer.mozilla.org/en-US/Firefox/Releases/36#Interfaces.2FAPIs.2FDOM
user_pref("dom.vr.enabled",					false);

// disable notifications
user_pref("dom.webnotifications.enabled",			false);

// disable webGL
// https://www.contextis.com/resources/blog/webgl-new-dimension-browser-exploitation/
user_pref("webgl.disabled",					true);
// https://bugzilla.mozilla.org/show_bug.cgi?id=1171228
// https://developer.mozilla.org/en-US/docs/Web/API/WEBGL_debug_renderer_info
user_pref("webgl.enable-debug-renderer-info",			false);
// somewhat related...
//user_pref("pdfjs.enableWebGL",		false);

/******************************************************************************
 * Misc                                                                       *
 *                                                                            *
 ******************************************************************************/

// Disable face detection by default
user_pref("camera.control.face_detection.enabled",		false);

// Default search engine
//user_pref("browser.search.defaultenginename",		"DuckDuckGo");

// http://kb.mozillazine.org/Clipboard.autocopy
user_pref("clipboard.autocopy",					false);

// Display an error message indicating the entered information is not a valid
// URL instead of asking from google.
// http://kb.mozillazine.org/Keyword.enabled#Caveats
user_pref("keyword.enabled",					false);

// Don't trim HTTP off of URLs in the address bar.
// https://bugzilla.mozilla.org/show_bug.cgi?id=665580
user_pref("browser.urlbar.trimURLs",				false);

// Don't try to guess where i'm trying to go!!! e.g.: "http://foo" -> "http://(prefix)foo(suffix)"
// http://www-archive.mozilla.org/docs/end-user/domain-guessing.html
user_pref("browser.fixup.alternate.enabled",			false);

// https://trac.torproject.org/projects/tor/wiki/doc/TorifyHOWTO/WebBrowsers
user_pref("network.proxy.socks_remote_dns",			true);

// We not want to monitoring the connection state of users 
// https://trac.torproject.org/projects/tor/ticket/18945
user_pref("network.manage-offline-status",		false);

// Mixed content stuff
// https://developer.mozilla.org/en-US/docs/Site_Compatibility_for_Firefox_23#Non-SSL_contents_on_SSL_pages_are_blocked_by_default
// https://blog.mozilla.org/tanvi/2013/04/10/mixed-content-blocking-enabled-in-firefox-23/
user_pref("security.mixed_content.block_active_content",	true);
// Mixed Passive Content (a.k.a. Mixed Display Content).
user_pref("security.mixed_content.block_display_content",	true);

// https://secure.wikimedia.org/wikibooks/en/wiki/Grsecurity/Application-specific_Settings#Firefox_.28or_Iceweasel_in_Debian.29
user_pref("javascript.options.methodjit.chrome",		false);
user_pref("javascript.options.methodjit.content",		false);

// CIS Mozilla Firefox 24 ESR v1.0.0 - 3.7 Disable JAR from opening Unsafe File Types
// http://kb.mozillazine.org/Network.jar.open-unsafe-types
user_pref("network.jar.open-unsafe-types",			false);

// CIS 2.7.4 Disable Scripting of Plugins by JavaScript
user_pref("security.xpconnect.plugin.unrestricted",		false);

// CIS Mozilla Firefox 24 ESR v1.0.0 - 3.8 Set File URI Origin Policy
// http://kb.mozillazine.org/Security.fileuri.strict_origin_policy
user_pref("security.fileuri.strict_origin_policy",		true);

// CIS 2.3.6 Disable Displaying Javascript in History URLs
// http://kb.mozillazine.org/Browser.urlbar.filter.javascript
user_pref("browser.urlbar.filter.javascript",			true);

// http://asmjs.org/
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-29/
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-50/
// https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-2712
user_pref("javascript.options.asmjs",				false);

// https://wiki.mozilla.org/SVGOpenTypeFonts
// the iSEC Partners Report recommends to disable this
user_pref("gfx.font_rendering.opentype_svg.enabled",		false);

// https://bugzil.la/654550
// https://github.com/pyllyukko/user.js/issues/9#issuecomment-100468785
// https://github.com/pyllyukko/user.js/issues/9#issuecomment-148922065
user_pref("media.video_stats.enabled",				false);

// Don't reveal build ID
// Value taken from Tor Browser
// https://bugzil.la/583181
user_pref("general.buildID.override",				"20100101");

// Prevent font fingerprinting
// https://browserleaks.com/fonts
// https://github.com/pyllyukko/user.js/issues/120
user_pref("browser.display.use_document_fonts",			0);

/******************************************************************************
 * extensions / plugins                                                       *
 *                                                                            *
 ******************************************************************************/

// Ensure you have a security delay when installing add-ons (milliseconds)
// http://kb.mozillazine.org/Disable_extension_install_delay_-_Firefox
// http://www.squarefree.com/2004/07/01/race-conditions-in-security-dialogs/
user_pref("security.dialog_enable_delay",			1000);

// Require signatures
//user_pref("xpinstall.signatures.required",		true);

// Opt-out of add-on metadata updates
// https://blog.mozilla.org/addons/how-to-opt-out-of-add-on-metadata-updates/
user_pref("extensions.getAddons.cache.enabled",			false);

// Flash plugin state - never activate
user_pref("plugin.state.flash",					0);

// disable Gnome Shell Integration
user_pref("plugin.state.libgnome-shell-browser-plugin",		0);

// disable the bundled OpenH264 video codec
// http://forums.mozillazine.org/viewtopic.php?p=13845077&sid=28af2622e8bd8497b9113851676846b1#p13845077
//user_pref("media.gmp-provider.enabled",		false);

// https://wiki.mozilla.org/Firefox/Click_To_Play
// https://blog.mozilla.org/security/2012/10/11/click-to-play-plugins-blocklist-style/
user_pref("plugins.click_to_play",				true);

// Updates addons automatically
// https://blog.mozilla.org/addons/how-to-turn-off-add-on-updates/
user_pref("extensions.update.enabled",				true);

// http://kb.mozillazine.org/Extensions.blocklist.enabled
user_pref("extensions.blocklist.enabled",			true);

/******************************************************************************
 * firefox features / components                                              *
 *                                                                            *
 ******************************************************************************/

// WebIDE
// https://trac.torproject.org/projects/tor/ticket/16222
user_pref("devtools.webide.enabled",				false);
user_pref("devtools.webide.autoinstallADBHelper",		false);
user_pref("devtools.webide.autoinstallFxdtAdapters",		false);

// disable remote debugging
// https://developer.mozilla.org/docs/Tools/Remote_Debugging/Debugging_Firefox_Desktop#Enable_remote_debugging
// https://developer.mozilla.org/en-US/docs/Tools/Tools_Toolbox#Advanced_settings
user_pref("devtools.debugger.remote-enabled",			false);
// "to use developer tools in the context of the browser itself, and not only web content"
user_pref("devtools.chrome.enabled",				false);
// https://developer.mozilla.org/en-US/docs/Tools/Remote_Debugging/Debugging_Firefox_Desktop#Firefox_37_onwards
user_pref("devtools.debugger.force-local",			true);

// https://wiki.mozilla.org/Platform/Features/Telemetry
// https://www.mozilla.org/en-US/legal/privacy/firefox.html#telemetry
// https://wiki.mozilla.org/Security/Reviews/Firefox6/ReviewNotes/telemetry
user_pref("toolkit.telemetry.enabled",				false);
// https://gecko.readthedocs.org/en/latest/toolkit/components/telemetry/telemetry/preferences.html
user_pref("toolkit.telemetry.unified",				false);
// https://wiki.mozilla.org/Telemetry/Experiments
user_pref("experiments.supported",				false);
user_pref("experiments.enabled",				false);

// Disable the UITour backend so there is no chance that a remote page
// can use it to confuse Tor Browser users.
user_pref("browser.uitour.enabled",				false);

// https://wiki.mozilla.org/Security/Tracking_protection
// https://support.mozilla.org/en-US/kb/tracking-protection-firefox
user_pref("privacy.trackingprotection.enabled",			true);
// https://support.mozilla.org/en-US/kb/tracking-protection-pbm
user_pref("privacy.trackingprotection.pbmode.enabled",		true);

// Resist fingerprinting via window.screen and CSS media queries and other techniques
// https://bugzil.la/418986
// https://bugzil.la/1281949
// https://bugzil.la/1281963
user_pref("privacy.resistFingerprinting",			true);

// Disable the built-in PDF viewer (CVE-2015-2743)
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-2743
user_pref("pdfjs.disabled",					true);

// Disable sending of the health report
// https://support.mozilla.org/en-US/kb/firefox-health-report-understand-your-browser-perf
user_pref("datareporting.healthreport.uploadEnabled",		false);
// disable collection of the data (the healthreport.sqlite* files)
user_pref("datareporting.healthreport.service.enabled",		false);
// https://gecko.readthedocs.org/en/latest/toolkit/components/telemetry/telemetry/preferences.html
user_pref("datareporting.policy.dataSubmissionEnabled",		false);

// Disable new tab tile ads & preload
// http://www.thewindowsclub.com/disable-remove-ad-tiles-from-firefox
// http://forums.mozillazine.org/viewtopic.php?p=13876331#p13876331
user_pref("browser.newtabpage.enhanced",			false);
user_pref("browser.newtab.preload",				false);
// https://wiki.mozilla.org/Tiles/Technical_Documentation#Ping
// https://gecko.readthedocs.org/en/latest/browser/browser/DirectoryLinksProvider.html#browser-newtabpage-directory-ping
user_pref("browser.newtabpage.directory.ping",			"");
// https://gecko.readthedocs.org/en/latest/browser/browser/DirectoryLinksProvider.html#browser-newtabpage-directory-source
user_pref("browser.newtabpage.directory.source",		"data:text/plain,{}");

// disable heartbeat
// https://wiki.mozilla.org/Advocacy/heartbeat
user_pref("browser.selfsupport.url",				"");

// Disable firefox hello
// https://wiki.mozilla.org/Loop
//user_pref("loop.enabled",		false);
// https://groups.google.com/d/topic/mozilla.dev.platform/nyVkCx-_sFw/discussion
user_pref("loop.logDomains",					false);

// CIS 2.1.1 Enable Auto Update
// This is disabled for now. it is better to patch through package management.
//user_pref("app.update.auto",		true);

// CIS 2.3.4 Block Reported Web Forgeries
// http://kb.mozillazine.org/Browser.safebrowsing.enabled
// http://kb.mozillazine.org/Safe_browsing
// https://support.mozilla.org/en-US/kb/how-does-phishing-and-malware-protection-work
// http://forums.mozillazine.org/viewtopic.php?f=39&t=2711237&p=12896849#p12896849
user_pref("browser.safebrowsing.enabled",			true);

// CIS 2.3.5 Block Reported Attack Sites
// http://kb.mozillazine.org/Browser.safebrowsing.malware.enabled
user_pref("browser.safebrowsing.malware.enabled",		true);

// Disable safe browsing remote lookups for downloaded files.
// This leaks information to google.
// https://www.mozilla.org/en-US/firefox/39.0/releasenotes/
// https://wiki.mozilla.org/Security/Application_Reputation
user_pref("browser.safebrowsing.downloads.remote.enabled",	false);

// Disable pocket
// https://support.mozilla.org/en-US/kb/save-web-pages-later-pocket-firefox
user_pref("browser.pocket.enabled",				false);
// https://github.com/pyllyukko/user.js/issues/143
user_pref("extensions.pocket.enabled",				false);

/******************************************************************************
 * automatic connections                                                      *
 *                                                                            *
 ******************************************************************************/

// Disable link prefetching
// http://kb.mozillazine.org/Network.prefetch-next
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Link_prefetching_FAQ#Is_there_a_preference_to_disable_link_prefetching.3F
user_pref("network.prefetch-next",				false);

// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_geolocation-for-default-search-engine
user_pref("browser.search.geoip.url",				"");

// http://kb.mozillazine.org/Network.dns.disablePrefetch
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Controlling_DNS_prefetching
user_pref("network.dns.disablePrefetch",			true);
user_pref("network.dns.disablePrefetchFromHTTPS",		true);

// https://bugzilla.mozilla.org/show_bug.cgi?id=1228457
user_pref("network.dns.blockDotOnion",				true);

// https://wiki.mozilla.org/Privacy/Reviews/Necko
user_pref("network.predictor.enabled",				false);
// https://wiki.mozilla.org/Privacy/Reviews/Necko#Principle:_Real_Choice
user_pref("network.seer.enabled",				false);

// http://kb.mozillazine.org/Browser.search.suggest.enabled
user_pref("browser.search.suggest.enabled",			false);
// Disable "Show search suggestions in location bar results"
user_pref("browser.urlbar.suggest.searches",			false);

// Disable SSDP
// https://bugzil.la/1111967
user_pref("browser.casting.enabled",				false);

// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_media-capabilities
// https://andreasgal.com/2014/10/14/openh264-now-in-firefox/
user_pref("media.gmp-gmpopenh264.enabled",			false);
user_pref("media.gmp-manager.url",				"");

// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_speculative-pre-connections
// https://bugzil.la/814169
user_pref("network.http.speculative-parallel-limit",		0);

// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_mozilla-content
user_pref("browser.aboutHomeSnippets.updateUrl",		"");

// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_auto-update-checking
user_pref("browser.search.update",				false);

/******************************************************************************
 * HTTP                                                                       *
 *                                                                            *
 ******************************************************************************/

// Disallow NTLMv1
// https://bugzilla.mozilla.org/show_bug.cgi?id=828183
user_pref("network.negotiate-auth.allow-insecure-ntlm-v1",	false);
// it is still allowed through HTTPS. uncomment the following to disable it completely.
//user_pref("network.negotiate-auth.allow-insecure-ntlm-v1-https",		false);

// https://bugzilla.mozilla.org/show_bug.cgi?id=855326
user_pref("security.csp.experimentalEnabled",			true);

// CSP https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy
user_pref("security.csp.enable",				true);

// Subresource integrity
// https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
// https://wiki.mozilla.org/Security/Subresource_Integrity
user_pref("security.sri.enable",				true);

// DNT HTTP header
// https://www.mozilla.org/en-US/firefox/dnt/
// https://en.wikipedia.org/wiki/Do_not_track_header
// https://dnt-dashboard.mozilla.org
// https://github.com/pyllyukko/user.js/issues/11
//user_pref("privacy.donottrackheader.enabled",		true);

// http://kb.mozillazine.org/Network.http.sendRefererHeader#0
// https://bugzilla.mozilla.org/show_bug.cgi?id=822869
// Send a referer header with the target URI as the source
//user_pref("network.http.sendRefererHeader",			1);
user_pref("network.http.referer.spoofSource",			true);

// CIS 2.5.1 Accept Only 1st Party Cookies
// http://kb.mozillazine.org/Network.cookie.cookieBehavior#1
// This breaks a number of payment gateways so you may need to comment it out.
user_pref("network.cookie.cookieBehavior",			1);
// Make sure that third-party cookies (if enabled) never persist beyond the session.
// https://feeding.cloud.geek.nz/posts/tweaking-cookies-for-privacy-in-firefox/
// http://kb.mozillazine.org/Network.cookie.thirdparty.sessionOnly
// https://developer.mozilla.org/en-US/docs/Cookies_Preferences_in_Mozilla#network.cookie.thirdparty.sessionOnly
user_pref("network.cookie.thirdparty.sessionOnly",		true);

// user-agent
//user_pref("general.useragent.override",		"Mozilla/5.0 (Windows NT 6.1; rv:31.0) Gecko/20100101 Firefox/31.0");

/******************************************************************************
 * Caching                                                                    *
 *                                                                            *
 ******************************************************************************/

// http://kb.mozillazine.org/Browser.sessionstore.postdata
// NOTE: relates to CIS 2.5.7
user_pref("browser.sessionstore.postdata",			0);
// http://kb.mozillazine.org/Browser.sessionstore.enabled
user_pref("browser.sessionstore.enabled",			false);

// http://kb.mozillazine.org/Browser.cache.offline.enable
user_pref("browser.cache.offline.enable",			false);

// Always use private browsing
// https://support.mozilla.org/en-US/kb/Private-Browsing
// https://wiki.mozilla.org/PrivateBrowsing
user_pref("browser.privatebrowsing.autostart",			true);
user_pref("extensions.ghostery.privateBrowsing",		true);

// Clear history when Firefox closes
// https://support.mozilla.org/en-US/kb/Clear%20Recent%20History#w_how-do-i-make-firefox-clear-my-history-automatically
user_pref("privacy.sanitize.sanitizeOnShutdown",		true);
user_pref("privacy.clearOnShutdown.cache",			true);
user_pref("privacy.clearOnShutdown.cookies",			true);
user_pref("privacy.clearOnShutdown.downloads",			true);
user_pref("privacy.clearOnShutdown.formdata",			true);
user_pref("privacy.clearOnShutdown.history",			true);
user_pref("privacy.clearOnShutdown.offlineApps",		true);
user_pref("privacy.clearOnShutdown.passwords",			true);
user_pref("privacy.clearOnShutdown.sessions",			true);
//user_pref("privacy.clearOnShutdown.siteSettings",		false);

// don't remember browsing history
user_pref("places.history.enabled",				false);

// The cookie expires at the end of the session (when the browser closes).
// http://kb.mozillazine.org/Network.cookie.lifetimePolicy#2
user_pref("network.cookie.lifetimePolicy",			2);

// http://kb.mozillazine.org/Browser.cache.disk.enable
user_pref("browser.cache.disk.enable",				false);

// http://kb.mozillazine.org/Browser.cache.memory.enable
//user_pref("browser.cache.memory.enable",		false);

// CIS Version 1.2.0 October 21st, 2011 2.5.8 Disable Caching of SSL Pages
// http://kb.mozillazine.org/Browser.cache.disk_cache_ssl
user_pref("browser.cache.disk_cache_ssl",			false);

// CIS Version 1.2.0 October 21st, 2011 2.5.2 Disallow Credential Storage
user_pref("signon.rememberSignons",				false);

// OWASP ASVS V9.1
// https://bugzilla.mozilla.org/show_bug.cgi?id=956906
user_pref("signon.storeWhenAutocompleteOff",			false);

// CIS Version 1.2.0 October 21st, 2011 2.5.5 Delete Download History
// Zero (0) is an indication that no download history is retained for the current profile.
user_pref("browser.download.manager.retention",			0);

// CIS Version 1.2.0 October 21st, 2011 2.5.6 Delete Search and Form History
user_pref("browser.formfill.enable",				false);
user_pref("browser.formfill.expire_days",			0);

// CIS Version 1.2.0 October 21st, 2011 2.5.7 Clear SSL Form Session Data
// http://kb.mozillazine.org/Browser.sessionstore.privacy_level#2
// Store extra session data for unencrypted (non-HTTPS) sites only.
// NOTE: CIS says 1, we use 2
user_pref("browser.sessionstore.privacy_level",			2);

// https://bugzil.la/238789#c19
user_pref("browser.helperApps.deleteTempFileOnExit",		true);

// https://support.mozilla.org/en-US/questions/973320
// https://developer.mozilla.org/en-US/docs/Mozilla/Preferences/Preference_reference/browser.pagethumbnails.capturing_disabled
user_pref("browser.pagethumbnails.capturing_disabled",		true);

/******************************************************************************
 * UI related                                                                 *
 *                                                                            *
 ******************************************************************************/

// Webpages will not be able to affect the right-click menu
//user_pref("dom.event.contextmenu.enabled",		false);

// Disable "Are you sure you want to leave this page?" popups on page close
// https://support.mozilla.org/en-US/questions/1043508
// Does not prevent JS leaks of the page close event.
// https://developer.mozilla.org/en-US/docs/Web/Events/beforeunload
//user_pref("dom.disable_beforeunload",    true);

// CIS 2.3.2 Disable Downloading on Desktop
user_pref("browser.download.folderList",			2);

// always ask the user where to download
// https://developer.mozilla.org/en/Download_Manager_preferences
user_pref("browser.download.useDownloadDir",			false);

// https://wiki.mozilla.org/Privacy/Reviews/New_Tab
user_pref("browser.newtabpage.enabled",				false);
// https://support.mozilla.org/en-US/kb/new-tab-page-show-hide-and-customize-top-sites#w_how-do-i-turn-the-new-tab-page-off
user_pref("browser.newtab.url",					"about:blank");

// CIS Version 1.2.0 October 21st, 2011 2.1.2 Enable Auto Notification of Outdated Plugins
// https://wiki.mozilla.org/Firefox3.6/Plugin_Update_Awareness_Security_Review
user_pref("plugins.update.notifyUser",				true);

// CIS Version 1.2.0 October 21st, 2011 2.1.3 Enable Information Bar for Outdated Plugins
user_pref("plugins.hide_infobar_for_outdated_plugin",		false);

// CIS Mozilla Firefox 24 ESR v1.0.0 - 3.6 Enable IDN Show Punycode
// http://kb.mozillazine.org/Network.IDN_show_punycode
user_pref("network.IDN_show_punycode",				true);

// http://kb.mozillazine.org/About:config_entries#Browser
// http://kb.mozillazine.org/Inline_autocomplete
user_pref("browser.urlbar.autoFill",				false);
user_pref("browser.urlbar.autoFill.typed",			false);

// https://www.labnol.org/software/browsers/prevent-firefox-showing-bookmarks-address-location-bar/3636/
// http://kb.mozillazine.org/Browser.urlbar.maxRichResults
// "Setting the preference to 0 effectively disables the Location Bar dropdown entirely."
user_pref("browser.urlbar.maxRichResults",			0);

// https://blog.mozilla.org/security/2010/03/31/plugging-the-css-history-leak/
// https://dbaron.org/mozilla/visited-privacy
user_pref("layout.css.visited_links_enabled",			false);

// http://kb.mozillazine.org/Places.frecency.unvisited%28place_type%29Bonus

// http://kb.mozillazine.org/Disabling_autocomplete_-_Firefox#Firefox_3.5
user_pref("browser.urlbar.autocomplete.enabled",		false);

// http://kb.mozillazine.org/Signon.autofillForms
// https://www.torproject.org/projects/torbrowser/design/#identifier-linkability
user_pref("signon.autofillForms",				false);

// do not check if firefox is the default browser
user_pref("browser.shell.checkDefaultBrowser",			false);

// CIS Version 1.2.0 October 21st, 2011 2.5.3 Disable Prompting for Credential Storage
user_pref("security.ask_for_password",				0);

/******************************************************************************
 * TLS / HTTPS / OCSP related stuff                                           *
 *                                                                            *
 ******************************************************************************/

// https://blog.mozilla.org/security/2012/11/01/preloading-hsts/
// https://wiki.mozilla.org/Privacy/Features/HSTS_Preload_List
user_pref("network.stricttransportsecurity.preloadlist",	true);

// CIS Version 1.2.0 October 21st, 2011 2.2.4 Enable Online Certificate Status Protocol
user_pref("security.OCSP.enabled",				1);

// https://blog.mozilla.org/security/2013/07/29/ocsp-stapling-in-firefox/
user_pref("security.ssl.enable_ocsp_stapling",			true);

// require certificate revocation check through OCSP protocol.
// NOTICE: this leaks information about the sites you visit to the CA.
user_pref("security.OCSP.require",				true);

// https://www.blackhat.com/us-13/briefings.html#NextGen
// https://media.blackhat.com/us-13/US-13-Daigniere-TLS-Secrets-Slides.pdf
// https://media.blackhat.com/us-13/US-13-Daigniere-TLS-Secrets-WP.pdf
// https://bugzil.la/917049
// https://bugzil.la/967977
user_pref("security.ssl.disable_session_identifiers",		true);

// TLS 1.[012]
// http://kb.mozillazine.org/Security.tls.version.max
// 1 = TLS 1.0 is the minimum required / maximum supported encryption protocol. (This is the current default for the maximum supported version.)
// 2 = TLS 1.1 is the minimum required / maximum supported encryption protocol.
user_pref("security.tls.version.min",				1);
user_pref("security.tls.version.max",				4);

// TLS version fallback
user_pref("security.tls.version.fallback-limit",		3);

// pinning
// https://wiki.mozilla.org/SecurityEngineering/Public_Key_Pinning#How_to_use_pinning
// "2. Strict. Pinning is always enforced."
user_pref("security.cert_pinning.enforcement_level",		2);

// disallow SHA-1
// https://bugzilla.mozilla.org/show_bug.cgi?id=1302140
//user_pref("security.pki.sha1_enforcement_level",		1);

// https://wiki.mozilla.org/Security:Renegotiation#security.ssl.treat_unsafe_negotiation_as_broken
// see also CVE-2009-3555
user_pref("security.ssl.treat_unsafe_negotiation_as_broken",	true);

// https://wiki.mozilla.org/Security:Renegotiation#security.ssl.require_safe_negotiation
// this makes browsing next to impossible=) (13.2.2012)
// update: the world is not ready for this! (6.5.2014)
// see also CVE-2009-3555
//user_pref("security.ssl.require_safe_negotiation",		true);

// https://support.mozilla.org/en-US/kb/certificate-pinning-reports
//
// we could also disable security.ssl.errorReporting.enabled, but I think it's
// good to leave the option to report potentially malicious sites if the user
// chooses to do so.
//
// you can test this at https://pinningtest.appspot.com/
user_pref("security.ssl.errorReporting.automatic",		false);

// http://kb.mozillazine.org/Browser.ssl_override_behavior
// Pre-populate the current URL but do not pre-fetch the certificate.
user_pref("browser.ssl_override_behavior",			1);

/******************************************************************************
 * CIPHERS                                                                    *
 *                                                                            *
 * you can debug the SSL handshake with tshark:                               *
 *     tshark -t ad -n -i wlan0 -T text -V -R ssl.handshake                   *
 ******************************************************************************/

// disable null ciphers
user_pref("security.ssl3.rsa_null_sha",				false);
user_pref("security.ssl3.rsa_null_md5",				false);
user_pref("security.ssl3.ecdhe_rsa_null_sha",			false);
user_pref("security.ssl3.ecdhe_ecdsa_null_sha",			false);
user_pref("security.ssl3.ecdh_rsa_null_sha",			false);
user_pref("security.ssl3.ecdh_ecdsa_null_sha",			false);

// SEED
// https://en.wikipedia.org/wiki/SEED
user_pref("security.ssl3.rsa_seed_sha",				false);

// 40 bits...
user_pref("security.ssl3.rsa_rc4_40_md5",			false);
user_pref("security.ssl3.rsa_rc2_40_md5",			false);

// 56 bits
user_pref("security.ssl3.rsa_1024_rc4_56_sha",			false);

// 128 bits
user_pref("security.ssl3.rsa_camellia_128_sha",			false);
user_pref("security.ssl3.ecdhe_rsa_aes_128_sha",		false);
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_sha",		false);
user_pref("security.ssl3.ecdh_rsa_aes_128_sha",			false);
user_pref("security.ssl3.ecdh_ecdsa_aes_128_sha",		false);
user_pref("security.ssl3.dhe_rsa_camellia_128_sha",		false);
user_pref("security.ssl3.dhe_rsa_aes_128_sha",			false);

// RC4 (CVE-2013-2566)
user_pref("security.ssl3.ecdh_ecdsa_rc4_128_sha",		false);
user_pref("security.ssl3.ecdh_rsa_rc4_128_sha",			false);
user_pref("security.ssl3.ecdhe_ecdsa_rc4_128_sha",		false);
user_pref("security.ssl3.ecdhe_rsa_rc4_128_sha",		false);
user_pref("security.ssl3.rsa_rc4_128_md5",			false);
user_pref("security.ssl3.rsa_rc4_128_sha",			false);
// https://developer.mozilla.org/en-US/Firefox/Releases/38#Security
// https://bugzil.la/1138882
// https://rc4.io/
user_pref("security.tls.unrestricted_rc4_fallback",		false);

// 3DES -> false because effective key size < 128
// https://en.wikipedia.org/wiki/3des#Security
// http://en.citizendium.org/wiki/Meet-in-the-middle_attack
// http://www-archive.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
user_pref("security.ssl3.dhe_dss_des_ede3_sha",			false);
user_pref("security.ssl3.dhe_rsa_des_ede3_sha",			false);
user_pref("security.ssl3.ecdh_ecdsa_des_ede3_sha",		false);
user_pref("security.ssl3.ecdh_rsa_des_ede3_sha",		false);
user_pref("security.ssl3.ecdhe_ecdsa_des_ede3_sha",		false);
user_pref("security.ssl3.ecdhe_rsa_des_ede3_sha",		false);
user_pref("security.ssl3.rsa_des_ede3_sha",			false);
user_pref("security.ssl3.rsa_fips_des_ede3_sha",		false);

// Ciphers with ECDH (without /e$/)
user_pref("security.ssl3.ecdh_rsa_aes_256_sha",			false);
user_pref("security.ssl3.ecdh_ecdsa_aes_256_sha",		false);

// 256 bits without PFS
user_pref("security.ssl3.rsa_camellia_256_sha",			false);

// Ciphers with ECDHE and > 128bits
user_pref("security.ssl3.ecdhe_rsa_aes_256_sha",		true);
user_pref("security.ssl3.ecdhe_ecdsa_aes_256_sha",		true);

// GCM, yes please!
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256",	true);
user_pref("security.ssl3.ecdhe_rsa_aes_128_gcm_sha256",		true);

// ChaCha20 and Poly1305. Supported since Firefox 47.
// https://www.mozilla.org/en-US/firefox/47.0/releasenotes/
// https://tools.ietf.org/html/rfc7905
// https://bugzil.la/917571
// https://bugzil.la/1247860
// https://cr.yp.to/chacha.html
user_pref("security.ssl3.ecdhe_ecdsa_chacha20_poly1305_sha256",	true);
user_pref("security.ssl3.ecdhe_rsa_chacha20_poly1305_sha256",	true);

// Susceptible to the logjam attack - https://weakdh.org/
user_pref("security.ssl3.dhe_rsa_camellia_256_sha",		false);
user_pref("security.ssl3.dhe_rsa_aes_256_sha",			false);

// Ciphers with DSA (max 1024 bits)
user_pref("security.ssl3.dhe_dss_aes_128_sha",			false);
user_pref("security.ssl3.dhe_dss_aes_256_sha",			false);
user_pref("security.ssl3.dhe_dss_camellia_128_sha",		false);
user_pref("security.ssl3.dhe_dss_camellia_256_sha",		false);

// Fallbacks due compatibility reasons
user_pref("security.ssl3.rsa_aes_256_sha",			true);
user_pref("security.ssl3.rsa_aes_128_sha",			true);
