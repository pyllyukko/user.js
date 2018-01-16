/*******************************************************************************
// This file has been created by create_locked_pref.sh
//
// It's equivalent to the user.js with the only difference that the settings are
// locked and cannot be changed by the Firefox user or Firefox itself.
//
// NOTE: Use this in the system-wide configuration only and only if you want the
//       settings to be locked.
//       Take a look here:
//  https://github.com/pyllyukko/user.js#system-wide-installation-all-platforms
/*******************************************************************************


/******************************************************************************
 * user.js                                                                    *
 * https://github.com/pyllyukko/user.js                                       *
 ******************************************************************************/

/******************************************************************************
 * SECTION: HTML5 / APIs / DOM                                                *
 ******************************************************************************/

// PREF: Disable Service Workers
// https://developer.mozilla.org/en-US/docs/Web/API/Worker
// https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorker_API
// https://wiki.mozilla.org/Firefox/Push_Notifications#Service_Workers
// NOTICE: Disabling ServiceWorkers breaks functionality on some sites (Google Street View...)
// Unknown security implications
// CVE-2016-5259, CVE-2016-2812, CVE-2016-1949, CVE-2016-5287 (fixed)
lockPref("dom.serviceWorkers.enabled",				false);

// PREF: Disable Web Workers
// https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers
// https://www.w3schools.com/html/html5_webworkers.asp
// NOTICE: Disabling Web Workers breaks "Download as ZIP" functionality on https://mega.nz/, WhatsApp Web and probably others
lockPref("dom.workers.enabled",					false);

// PREF: Disable web notifications
// https://support.mozilla.org/t5/Firefox/I-can-t-find-Firefox-menu-I-m-trying-to-opt-out-of-Web-Push-and/m-p/1317495#M1006501
lockPref("dom.webnotifications.enabled",			false);

// PREF: Disable DOM timing API
// https://wiki.mozilla.org/Security/Reviews/Firefox/NavigationTimingAPI
// https://www.w3.org/TR/navigation-timing/#privacy
lockPref("dom.enable_performance",				false);

// PREF: Make sure the User Timing API does not provide a new high resolution timestamp
// https://trac.torproject.org/projects/tor/ticket/16336
// https://www.w3.org/TR/2013/REC-user-timing-20131212/#privacy-security
lockPref("dom.enable_user_timing",				false);

// PREF: Disable Web Audio API
// https://bugzilla.mozilla.org/show_bug.cgi?id=1288359
lockPref("dom.webaudio.enabled",				false);

// PREF: Disable Location-Aware Browsing (geolocation)
// https://www.mozilla.org/en-US/firefox/geolocation/
lockPref("geo.enabled",					false);

// PREF: When geolocation is enabled, use Mozilla geolocation service instead of Google
// https://bugzilla.mozilla.org/show_bug.cgi?id=689252
lockPref("geo.wifi.uri", "https://location.services.mozilla.com/v1/geolocate?key=%MOZILLA_API_KEY%");

// PREF: When geolocation is enabled, don't log geolocation requests to the console
lockPref("geo.wifi.logging.enabled", false);

// PREF: Disable raw TCP socket support (mozTCPSocket)
// https://trac.torproject.org/projects/tor/ticket/18863
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-97/
// https://developer.mozilla.org/docs/Mozilla/B2G_OS/API/TCPSocket
lockPref("dom.mozTCPSocket.enabled",				false);

// PREF: Disable DOM storage (disabled)
// http://kb.mozillazine.org/Dom.storage.enabled
// https://html.spec.whatwg.org/multipage/webstorage.html
// NOTICE-DISABLED: Disabling DOM storage is known to cause`TypeError: localStorage is null` errors
//lockPref("dom.storage.enabled",		false);

// PREF: Disable leaking network/browser connection information via Javascript
// Network Information API provides general information about the system's connection type (WiFi, cellular, etc.)
// https://developer.mozilla.org/en-US/docs/Web/API/Network_Information_API
// https://wicg.github.io/netinfo/#privacy-considerations
// https://bugzilla.mozilla.org/show_bug.cgi?id=960426
lockPref("dom.netinfo.enabled",				false);

// PREF: Disable network API (Firefox < 32)
// https://developer.mozilla.org/en-US/docs/Web/API/Connection/onchange
// https://www.torproject.org/projects/torbrowser/design/#fingerprinting-defenses
lockPref("dom.network.enabled",				false);

// PREF: Disable WebRTC entirely to prevent leaking internal IP addresses (Firefox < 42)
// NOTICE: Disabling WebRTC breaks peer-to-peer file sharing tools (reep.io ...)
lockPref("media.peerconnection.enabled",			false);

// PREF: Don't reveal your internal IP when WebRTC is enabled (Firefox >= 42)
// https://wiki.mozilla.org/Media/WebRTC/Privacy
// https://github.com/beefproject/beef/wiki/Module%3A-Get-Internal-IP-WebRTC
lockPref("media.peerconnection.ice.default_address_only",	true); // Firefox 42-51
lockPref("media.peerconnection.ice.no_host",			true); // Firefox >= 52

// PREF: Disable WebRTC getUserMedia, screen sharing, audio capture, video capture
// https://wiki.mozilla.org/Media/getUserMedia
// https://blog.mozilla.org/futurereleases/2013/01/12/capture-local-camera-and-microphone-streams-with-getusermedia-now-enabled-in-firefox/
// https://developer.mozilla.org/en-US/docs/Web/API/Navigator
lockPref("media.navigator.enabled",				false);
lockPref("media.navigator.video.enabled",			false);
lockPref("media.getusermedia.screensharing.enabled",		false);
lockPref("media.getusermedia.audiocapture.enabled",		false);

// PREF: Disable battery API (Firefox < 52)
// https://developer.mozilla.org/en-US/docs/Web/API/BatteryManager
// https://bugzilla.mozilla.org/show_bug.cgi?id=1313580
lockPref("dom.battery.enabled",				false);

// PREF: Disable telephony API
// https://wiki.mozilla.org/WebAPI/Security/WebTelephony
lockPref("dom.telephony.enabled",				false);

// PREF: Disable "beacon" asynchronous HTTP transfers (used for analytics)
// https://developer.mozilla.org/en-US/docs/Web/API/navigator.sendBeacon
lockPref("beacon.enabled",					false);

// PREF: Disable clipboard event detection (onCut/onCopy/onPaste) via Javascript
// NOTICE: Disabling clipboard events breaks Ctrl+C/X/V copy/cut/paste functionaility in JS-based web applications (Google Docs...)
// https://developer.mozilla.org/en-US/docs/Mozilla/Preferences/Preference_reference/dom.event.clipboardevents.enabled
lockPref("dom.event.clipboardevents.enabled",			false);

// PREF: Disable "copy to clipboard" functionality via Javascript (Firefox >= 41)
// NOTICE: Disabling clipboard operations will break legitimate JS-based "copy to clipboard" functionality
// https://hg.mozilla.org/mozilla-central/rev/2f9f8ea4b9c3
lockPref("dom.allow_cut_copy", false);

// PREF: Disable speech recognition
// https://dvcs.w3.org/hg/speech-api/raw-file/tip/speechapi.html
// https://developer.mozilla.org/en-US/docs/Web/API/SpeechRecognition
// https://wiki.mozilla.org/HTML5_Speech_API
lockPref("media.webspeech.recognition.enable",			false);

// PREF: Disable speech synthesis
// https://developer.mozilla.org/en-US/docs/Web/API/SpeechSynthesis
lockPref("media.webspeech.synth.enabled",			false);

// PREF: Disable sensor API
// https://wiki.mozilla.org/Sensor_API
lockPref("device.sensors.enabled",				false);

// PREF: Disable pinging URIs specified in HTML <a> ping= attributes
// http://kb.mozillazine.org/Browser.send_pings
lockPref("browser.send_pings",					false);

// PREF: When browser pings are enabled, only allow pinging the same host as the origin page
// http://kb.mozillazine.org/Browser.send_pings.require_same_host
lockPref("browser.send_pings.require_same_host",		true);

// PREF: Disable IndexedDB (disabled)
// https://developer.mozilla.org/en-US/docs/IndexedDB
// https://en.wikipedia.org/wiki/Indexed_Database_API
// https://wiki.mozilla.org/Security/Reviews/Firefox4/IndexedDB_Security_Review
// http://forums.mozillazine.org/viewtopic.php?p=13842047
// https://github.com/pyllyukko/user.js/issues/8
// NOTICE-DISABLED: IndexedDB could be used for tracking purposes, but is required for some add-ons to work (notably uBlock), so is left enabled
//lockPref("dom.indexedDB.enabled",		false);

// TODO: "Access Your Location" "Maintain Offline Storage" "Show Notifications"

// PREF: Disable gamepad API to prevent USB device enumeration
// https://www.w3.org/TR/gamepad/
// https://trac.torproject.org/projects/tor/ticket/13023
lockPref("dom.gamepad.enabled",				false);

// PREF: Disable virtual reality devices APIs
// https://developer.mozilla.org/en-US/Firefox/Releases/36#Interfaces.2FAPIs.2FDOM
// https://developer.mozilla.org/en-US/docs/Web/API/WebVR_API
lockPref("dom.vr.enabled",					false);

// PREF: Disable vibrator API
lockPref("dom.vibrator.enabled",           false);

// PREF: Disable resource timing API
// https://www.w3.org/TR/resource-timing/#privacy-security
lockPref("dom.enable_resource_timing",				false);

// PREF: Disable Archive API (Firefox < 54)
// https://wiki.mozilla.org/WebAPI/ArchiveAPI
// https://bugzilla.mozilla.org/show_bug.cgi?id=1342361
lockPref("dom.archivereader.enabled",				false);

// PREF: Disable webGL
// https://en.wikipedia.org/wiki/WebGL
// https://www.contextis.com/resources/blog/webgl-new-dimension-browser-exploitation/
lockPref("webgl.disabled",					true);
// PREF: When webGL is enabled, use the minimum capability mode
lockPref("webgl.min_capability_mode",				true);
// PREF: When webGL is enabled, disable webGL extensions
// https://developer.mozilla.org/en-US/docs/Web/API/WebGL_API#WebGL_debugging_and_testing
lockPref("webgl.disable-extensions",				true);
// PREF: When webGL is enabled, force enabling it even when layer acceleration is not supported
// https://trac.torproject.org/projects/tor/ticket/18603
lockPref("webgl.disable-fail-if-major-performance-caveat",	true);
// PREF: When webGL is enabled, do not expose information about the graphics driver
// https://bugzilla.mozilla.org/show_bug.cgi?id=1171228
// https://developer.mozilla.org/en-US/docs/Web/API/WEBGL_debug_renderer_info
lockPref("webgl.enable-debug-renderer-info",			false);
// somewhat related...
//lockPref("pdfjs.enableWebGL",					false);

// PREF: Spoof dual-core CPU
// https://trac.torproject.org/projects/tor/ticket/21675
// https://bugzilla.mozilla.org/show_bug.cgi?id=1360039
lockPref("dom.maxHardwareConcurrency",				2);

/******************************************************************************
 * SECTION: Misc                                                              *
 ******************************************************************************/

// PREF: Disable face detection
lockPref("camera.control.face_detection.enabled",		false);

// PREF: Set the default search engine to DuckDuckGo (disabled)
// https://support.mozilla.org/en-US/questions/948134
//lockPref("browser.search.defaultenginename",		"DuckDuckGo");
//lockPref("browser.search.order.1",				"DuckDuckGo");
//lockPref("keyword.URL", 							"https://duckduckgo.com/html/?q=!+");  

// PREF: Disable GeoIP lookup on your address to set default search engine region
// https://trac.torproject.org/projects/tor/ticket/16254
// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_geolocation-for-default-search-engine
lockPref("browser.search.countryCode",				"US");
lockPref("browser.search.region",				"US");
lockPref("browser.search.geoip.url",				"");

// PREF: Set Accept-Language HTTP header to en-US regardless of Firefox localization
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Language
lockPref("intl.accept_languages",				"en-us, en");

// PREF: Don't use OS values to determine locale, force using Firefox locale setting
// http://kb.mozillazine.org/Intl.locale.matchOS
lockPref("intl.locale.matchOS",				false);

// PREF: Don't use Mozilla-provided location-specific search engines
lockPref("browser.search.geoSpecificDefaults",			false);

// PREF: Do not automatically send selection to clipboard on some Linux platforms
// http://kb.mozillazine.org/Clipboard.autocopy
lockPref("clipboard.autocopy",					false);

// PREF: Prevent leaking application locale/date format using JavaScript
// https://bugzilla.mozilla.org/show_bug.cgi?id=867501
// https://hg.mozilla.org/mozilla-central/rev/52d635f2b33d
lockPref("javascript.use_us_english_locale",			true);

// PREF: Do not submit invalid URIs entered in the address bar to the default search engine
// http://kb.mozillazine.org/Keyword.enabled
lockPref("keyword.enabled",					false);

// PREF: Don't trim HTTP off of URLs in the address bar.
// https://bugzilla.mozilla.org/show_bug.cgi?id=665580
lockPref("browser.urlbar.trimURLs",				false);

// PREF: Don't try to guess domain names when entering an invalid domain name in URL bar
// http://www-archive.mozilla.org/docs/end-user/domain-guessing.html
lockPref("browser.fixup.alternate.enabled",			false);

// PREF: When browser.fixup.alternate.enabled is enabled, strip password from 'user:password@...' URLs
// https://github.com/pyllyukko/user.js/issues/290#issuecomment-303560851
lockPref("browser.fixup.hide_user_pass", true);

// PREF: Send DNS request through SOCKS when SOCKS proxying is in use
// https://trac.torproject.org/projects/tor/wiki/doc/TorifyHOWTO/WebBrowsers
lockPref("network.proxy.socks_remote_dns",			true);

// PREF: Don't monitor OS online/offline connection state
// https://trac.torproject.org/projects/tor/ticket/18945
lockPref("network.manage-offline-status",			false);

// PREF: Enforce Mixed Active Content Blocking
// https://support.mozilla.org/t5/Protect-your-privacy/Mixed-content-blocking-in-Firefox/ta-p/10990
// https://developer.mozilla.org/en-US/docs/Site_Compatibility_for_Firefox_23#Non-SSL_contents_on_SSL_pages_are_blocked_by_default
// https://blog.mozilla.org/tanvi/2013/04/10/mixed-content-blocking-enabled-in-firefox-23/
lockPref("security.mixed_content.block_active_content",	true);

// PREF: Enforce Mixed Passive Content blocking (a.k.a. Mixed Display Content)
// NOTICE: Enabling Mixed Display Content blocking can prevent images/styles... from loading properly when connection to the website is only partially secured
lockPref("security.mixed_content.block_display_content",	true);

// PREF: Disable JAR from opening Unsafe File Types
// http://kb.mozillazine.org/Network.jar.open-unsafe-types
// CIS Mozilla Firefox 24 ESR v1.0.0 - 3.7 
lockPref("network.jar.open-unsafe-types",			false);

// CIS 2.7.4 Disable Scripting of Plugins by JavaScript
// http://forums.mozillazine.org/viewtopic.php?f=7&t=153889
lockPref("security.xpconnect.plugin.unrestricted",		false);

// PREF: Set File URI Origin Policy
// http://kb.mozillazine.org/Security.fileuri.strict_origin_policy
// CIS Mozilla Firefox 24 ESR v1.0.0 - 3.8
lockPref("security.fileuri.strict_origin_policy",		true);

// PREF: Disable Displaying Javascript in History URLs
// http://kb.mozillazine.org/Browser.urlbar.filter.javascript
// CIS 2.3.6 
lockPref("browser.urlbar.filter.javascript",			true);

// PREF: Disable asm.js
// http://asmjs.org/
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-29/
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-50/
// https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-2712
lockPref("javascript.options.asmjs",				false);

// PREF: Disable SVG in OpenType fonts
// https://wiki.mozilla.org/SVGOpenTypeFonts
// https://github.com/iSECPartners/publications/tree/master/reports/Tor%20Browser%20Bundle
lockPref("gfx.font_rendering.opentype_svg.enabled",		false);

// PREF: Disable in-content SVG rendering (Firefox >= 53)
// NOTICE: Disabling SVG support breaks many UI elements on many sites
// https://bugzilla.mozilla.org/show_bug.cgi?id=1216893
// https://github.com/iSECPartners/publications/raw/master/reports/Tor%20Browser%20Bundle/Tor%20Browser%20Bundle%20-%20iSEC%20Deliverable%201.3.pdf#16
lockPref("svg.disabled", true);


// PREF: Disable video stats to reduce fingerprinting threat
// https://bugzilla.mozilla.org/show_bug.cgi?id=654550
// https://github.com/pyllyukko/user.js/issues/9#issuecomment-100468785
// https://github.com/pyllyukko/user.js/issues/9#issuecomment-148922065
lockPref("media.video_stats.enabled",				false);

// PREF: Don't reveal build ID
// Value taken from Tor Browser
// https://bugzilla.mozilla.org/show_bug.cgi?id=583181
lockPref("general.buildID.override",				"20100101");
lockPref("browser.startup.homepage_override.buildID",		"20100101");

// PREF: Prevent font fingerprinting
// https://browserleaks.com/fonts
// https://github.com/pyllyukko/user.js/issues/120
lockPref("browser.display.use_document_fonts",			0);

// PREF: Enable only whitelisted URL protocol handlers
// http://kb.mozillazine.org/Network.protocol-handler.external-default
// http://kb.mozillazine.org/Network.protocol-handler.warn-external-default
// http://kb.mozillazine.org/Network.protocol-handler.expose.%28protocol%29
// https://news.ycombinator.com/item?id=13047883
// https://bugzilla.mozilla.org/show_bug.cgi?id=167475
// https://github.com/pyllyukko/user.js/pull/285#issuecomment-298124005
// NOTICE: Disabling nonessential protocols breaks all interaction with custom protocols such as mailto:, irc:, magnet: ... and breaks opening third-party mail/messaging/torrent/... clients when clicking on links with these protocols
// TODO: Add externally-handled protocols from Windows 8.1 and Windows 10 (currently contains protocols only from Linux and Windows 7) that might pose a similar threat (see e.g. https://news.ycombinator.com/item?id=13044991)
// TODO: Add externally-handled protocols from Mac OS X that might pose a similar threat (see e.g. https://news.ycombinator.com/item?id=13044991)
// If you want to enable a protocol, set network.protocol-handler.expose.(protocol) to true and network.protocol-handler.external.(protocol) to:
//   * true, if the protocol should be handled by an external application
//   * false, if the protocol should be handled internally by Firefox
lockPref("network.protocol-handler.warn-external-default",	true);
lockPref("network.protocol-handler.external.http",		false);
lockPref("network.protocol-handler.external.https",		false);
lockPref("network.protocol-handler.external.javascript",	false);
lockPref("network.protocol-handler.external.moz-extension",	false);
lockPref("network.protocol-handler.external.ftp",		false);
lockPref("network.protocol-handler.external.file",		false);
lockPref("network.protocol-handler.external.about",		false);
lockPref("network.protocol-handler.external.chrome",		false);
lockPref("network.protocol-handler.external.blob",		false);
lockPref("network.protocol-handler.external.data",		false);
lockPref("network.protocol-handler.expose-all",		false);
lockPref("network.protocol-handler.expose.http",		true);
lockPref("network.protocol-handler.expose.https",		true);
lockPref("network.protocol-handler.expose.javascript",		true);
lockPref("network.protocol-handler.expose.moz-extension",	true);
lockPref("network.protocol-handler.expose.ftp",		true);
lockPref("network.protocol-handler.expose.file",		true);
lockPref("network.protocol-handler.expose.about",		true);
lockPref("network.protocol-handler.expose.chrome",		true);
lockPref("network.protocol-handler.expose.blob",		true);
lockPref("network.protocol-handler.expose.data",		true);

/******************************************************************************
 * SECTION: Extensions / plugins                                                       *
 ******************************************************************************/

// PREF: Ensure you have a security delay when installing add-ons (milliseconds)
// http://kb.mozillazine.org/Disable_extension_install_delay_-_Firefox
// http://www.squarefree.com/2004/07/01/race-conditions-in-security-dialogs/
lockPref("security.dialog_enable_delay",			1000);

// PREF: Require signatures
// https://wiki.mozilla.org/Addons/Extension_Signing
//lockPref("xpinstall.signatures.required",		true);

// PREF: Opt-out of add-on metadata updates
// https://blog.mozilla.org/addons/how-to-opt-out-of-add-on-metadata-updates/
lockPref("extensions.getAddons.cache.enabled",			false);

// PREF: Opt-out of themes (Persona) updates
// https://support.mozilla.org/t5/Firefox/how-do-I-prevent-autoamtic-updates-in-a-50-user-environment/td-p/144287
lockPref("lightweightThemes.update.enabled",			false);

// PREF: Disable Flash Player NPAPI plugin
// http://kb.mozillazine.org/Flash_plugin
lockPref("plugin.state.flash",					0);

// PREF: Disable Java NPAPI plugin
lockPref("plugin.state.java",					0);

// PREF: Disable sending Flash Player crash reports
lockPref("dom.ipc.plugins.flash.subprocess.crashreporter.enabled",	false);

// PREF: When Flash crash reports are enabled, don't send the visited URL in the crash report
lockPref("dom.ipc.plugins.reportCrashURL",			false);

// PREF: When Flash is enabled, download and use Mozilla SWF URIs blocklist
// https://bugzilla.mozilla.org/show_bug.cgi?id=1237198
// https://github.com/mozilla-services/shavar-plugin-blocklist
lockPref("browser.safebrowsing.blockedURIs.enabled", true);

// PREF: Disable Shumway (Mozilla Flash renderer)
// https://developer.mozilla.org/en-US/docs/Mozilla/Projects/Shumway
lockPref("shumway.disabled", true);

// PREF: Disable Gnome Shell Integration NPAPI plugin
lockPref("plugin.state.libgnome-shell-browser-plugin",		0);

// PREF: Disable the bundled OpenH264 video codec (disabled)
// http://forums.mozillazine.org/viewtopic.php?p=13845077&sid=28af2622e8bd8497b9113851676846b1#p13845077
//lockPref("media.gmp-provider.enabled",		false);

// PREF: Enable plugins click-to-play
// https://wiki.mozilla.org/Firefox/Click_To_Play
// https://blog.mozilla.org/security/2012/10/11/click-to-play-plugins-blocklist-style/
lockPref("plugins.click_to_play",				true);

// PREF: Updates addons automatically
// https://blog.mozilla.org/addons/how-to-turn-off-add-on-updates/
lockPref("extensions.update.enabled",				true);

// PREF: Enable add-on and certificate blocklists (OneCRL) from Mozilla
// https://wiki.mozilla.org/Blocklisting
// https://blocked.cdn.mozilla.net/
// http://kb.mozillazine.org/Extensions.blocklist.enabled
// http://kb.mozillazine.org/Extensions.blocklist.url
// https://blog.mozilla.org/security/2015/03/03/revoking-intermediate-certificates-introducing-onecrl/
// Updated at interval defined in extensions.blocklist.interval (default: 86400)
lockPref("extensions.blocklist.enabled",			true);
lockPref("services.blocklist.update_enabled",			true);

// PREF: Decrease system information leakage to Mozilla blocklist update servers
// https://trac.torproject.org/projects/tor/ticket/16931
lockPref("extensions.blocklist.url",				"https://blocklist.addons.mozilla.org/blocklist/3/%APP_ID%/%APP_VERSION%/");

/******************************************************************************
 * SECTION: Firefox (anti-)features / components                              *                            *
 ******************************************************************************/

// PREF: Disable WebIDE
// https://trac.torproject.org/projects/tor/ticket/16222
// https://developer.mozilla.org/docs/Tools/WebIDE
lockPref("devtools.webide.enabled",				false);
lockPref("devtools.webide.autoinstallADBHelper",		false);
lockPref("devtools.webide.autoinstallFxdtAdapters",		false);

// PREF: Disable remote debugging
// https://developer.mozilla.org/en-US/docs/Tools/Remote_Debugging/Debugging_Firefox_Desktop
// https://developer.mozilla.org/en-US/docs/Tools/Tools_Toolbox#Advanced_settings
lockPref("devtools.debugger.remote-enabled",			false);
lockPref("devtools.chrome.enabled",				false);
lockPref("devtools.debugger.force-local",			true);

// PREF: Disable Mozilla telemetry/experiments
// https://wiki.mozilla.org/Platform/Features/Telemetry
// https://wiki.mozilla.org/Privacy/Reviews/Telemetry
// https://wiki.mozilla.org/Telemetry
// https://www.mozilla.org/en-US/legal/privacy/firefox.html#telemetry
// https://support.mozilla.org/t5/Firefox-crashes/Mozilla-Crash-Reporter/ta-p/1715
// https://wiki.mozilla.org/Security/Reviews/Firefox6/ReviewNotes/telemetry
// https://gecko.readthedocs.io/en/latest/browser/experiments/experiments/manifest.html
// https://wiki.mozilla.org/Telemetry/Experiments
lockPref("toolkit.telemetry.enabled",				false);
lockPref("toolkit.telemetry.unified",				false);
lockPref("experiments.supported",				false);
lockPref("experiments.enabled",				false);
lockPref("experiments.manifest.uri",				"");

// PREF: Disallow Necko to do A/B testing
// https://trac.torproject.org/projects/tor/ticket/13170
lockPref("network.allow-experiments",				false);

// PREF: Disable sending Firefox crash reports to Mozilla servers
// https://wiki.mozilla.org/Breakpad
// http://kb.mozillazine.org/Breakpad
// https://dxr.mozilla.org/mozilla-central/source/toolkit/crashreporter
// https://bugzilla.mozilla.org/show_bug.cgi?id=411490
// A list of submitted crash reports can be found at about:crashes
lockPref("breakpad.reportURL",					"");

// PREF: Disable sending reports of tab crashes to Mozilla (about:tabcrashed), don't nag user about unsent crash reports
// https://hg.mozilla.org/mozilla-central/file/tip/browser/app/profile/firefox.js
lockPref("browser.tabs.crashReporting.sendReport",		false);
lockPref("browser.crashReports.unsubmittedCheck.enabled",	false);

// PREF: Disable FlyWeb (discovery of LAN/proximity IoT devices that expose a Web interface)
// https://wiki.mozilla.org/FlyWeb
// https://wiki.mozilla.org/FlyWeb/Security_scenarios
// https://docs.google.com/document/d/1eqLb6cGjDL9XooSYEEo7mE-zKQ-o-AuDTcEyNhfBMBM/edit
// http://www.ghacks.net/2016/07/26/firefox-flyweb
lockPref("dom.flyweb.enabled",					false);

// PREF: Disable the UITour backend
// https://trac.torproject.org/projects/tor/ticket/19047#comment:3
lockPref("browser.uitour.enabled",				false);

// PREF: Enable Firefox Tracking Protection
// https://wiki.mozilla.org/Security/Tracking_protection
// https://support.mozilla.org/en-US/kb/tracking-protection-firefox
// https://support.mozilla.org/en-US/kb/tracking-protection-pbm
// https://kontaxis.github.io/trackingprotectionfirefox/
// https://feeding.cloud.geek.nz/posts/how-tracking-protection-works-in-firefox/
lockPref("privacy.trackingprotection.enabled",			true);
lockPref("privacy.trackingprotection.pbmode.enabled",		true);

// PREF: Enable contextual identity Containers feature (Firefox >= 52)
// NOTICE: Containers are not available in Private Browsing mode
// https://wiki.mozilla.org/Security/Contextual_Identity_Project/Containers
lockPref("privacy.userContext.enabled",			true);

// PREF: Enable hardening against various fingerprinting vectors (Tor Uplift project)
// https://wiki.mozilla.org/Security/Tor_Uplift/Tracking
// https://bugzilla.mozilla.org/show_bug.cgi?id=1333933
lockPref("privacy.resistFingerprinting",			true);

// PREF: Disable the built-in PDF viewer
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-2743
// https://blog.mozilla.org/security/2015/08/06/firefox-exploit-found-in-the-wild/
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-69/
lockPref("pdfjs.disabled",					true);

// PREF: Disable collection/sending of the health report (healthreport.sqlite*)
// https://support.mozilla.org/en-US/kb/firefox-health-report-understand-your-browser-perf
// https://gecko.readthedocs.org/en/latest/toolkit/components/telemetry/telemetry/preferences.html
lockPref("datareporting.healthreport.uploadEnabled",		false);
lockPref("datareporting.healthreport.service.enabled",		false);
lockPref("datareporting.policy.dataSubmissionEnabled",		false);

// PREF: Disable Heartbeat  (Mozilla user rating telemetry)
// https://wiki.mozilla.org/Advocacy/heartbeat
// https://trac.torproject.org/projects/tor/ticket/19047
lockPref("browser.selfsupport.url",				"");

// PREF: Disable Firefox Hello (disabled) (Firefox < 49)
// https://wiki.mozilla.org/Loop
// https://support.mozilla.org/t5/Chat-and-share/Support-for-Hello-discontinued-in-Firefox-49/ta-p/37946
// NOTICE-DISABLED: Firefox Hello requires setting `media.peerconnection.enabled` and `media.getusermedia.screensharing.enabled` to true, `security.OCSP.require` to false to work.
//lockPref("loop.enabled",		false);

// PREF: Disable Firefox Hello metrics collection
// https://groups.google.com/d/topic/mozilla.dev.platform/nyVkCx-_sFw/discussion
lockPref("loop.logDomains",					false);

// PREF: Enable Auto Update (disabled)
// NOTICE: Fully automatic updates are disabled and left to package management systems on Linux. Windows users may want to change this setting.
// CIS 2.1.1
//lockPref("app.update.auto",					true);

// PREF: Enforce checking for Firefox updates
// http://kb.mozillazine.org/App.update.enabled
// NOTICE: Update check page might incorrectly report Firefox ESR as out-of-date
lockPref("app.update.enabled",                 true);

// PREF: Enable blocking reported web forgeries
// https://wiki.mozilla.org/Security/Safe_Browsing
// http://kb.mozillazine.org/Safe_browsing
// https://support.mozilla.org/en-US/kb/how-does-phishing-and-malware-protection-work
// http://forums.mozillazine.org/viewtopic.php?f=39&t=2711237&p=12896849#p12896849
// CIS 2.3.4
lockPref("browser.safebrowsing.enabled",			true); // Firefox < 50
lockPref("browser.safebrowsing.phishing.enabled",		true); // firefox >= 50

// PREF: Enable blocking reported attack sites
// http://kb.mozillazine.org/Browser.safebrowsing.malware.enabled
// CIS 2.3.5
lockPref("browser.safebrowsing.malware.enabled",		true);

// PREF: Disable querying Google Application Reputation database for downloaded binary files
// https://www.mozilla.org/en-US/firefox/39.0/releasenotes/
// https://wiki.mozilla.org/Security/Application_Reputation
lockPref("browser.safebrowsing.downloads.remote.enabled",	false);

// PREF: Disable Pocket
// https://support.mozilla.org/en-US/kb/save-web-pages-later-pocket-firefox
// https://github.com/pyllyukko/user.js/issues/143
lockPref("browser.pocket.enabled",				false);
lockPref("extensions.pocket.enabled",				false);

// PREF: Disable SHIELD
// https://support.mozilla.org/en-US/kb/shield
// https://bugzilla.mozilla.org/show_bug.cgi?id=1370801
lockPref("extensions.shield-recipe-client.enabled",		false);
lockPref("app.shield.optoutstudies.enabled",			false);

// PREF: Disable "Recommended by Pocket" in Firefox Quantum
lockPref("browser.newtabpage.activity-stream.feeds.section.topstories",	false);

/******************************************************************************
 * SECTION: Automatic connections                                             *
 ******************************************************************************/

// PREF: Disable prefetching of <link rel="next"> URLs
// http://kb.mozillazine.org/Network.prefetch-next
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Link_prefetching_FAQ#Is_there_a_preference_to_disable_link_prefetching.3F
lockPref("network.prefetch-next",				false);

// PREF: Disable DNS prefetching
// http://kb.mozillazine.org/Network.dns.disablePrefetch
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Controlling_DNS_prefetching
lockPref("network.dns.disablePrefetch",			true);
lockPref("network.dns.disablePrefetchFromHTTPS",		true);

// PREF: Disable the predictive service (Necko)
// https://wiki.mozilla.org/Privacy/Reviews/Necko
lockPref("network.predictor.enabled",				false);

// PREF: Reject .onion hostnames before passing the to DNS
// https://bugzilla.mozilla.org/show_bug.cgi?id=1228457
// RFC 7686
lockPref("network.dns.blockDotOnion",				true);

// PREF: Disable search suggestions in the search bar
// http://kb.mozillazine.org/Browser.search.suggest.enabled
lockPref("browser.search.suggest.enabled",			false);

// PREF: Disable "Show search suggestions in location bar results"
lockPref("browser.urlbar.suggest.searches",			false);
// PREF: When using the location bar, don't suggest URLs from browsing history
lockPref("browser.urlbar.suggest.history",			false);

// PREF: Disable SSDP
// https://bugzilla.mozilla.org/show_bug.cgi?id=1111967
lockPref("browser.casting.enabled",				false);

// PREF: Disable automatic downloading of OpenH264 codec
// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_media-capabilities
// https://andreasgal.com/2014/10/14/openh264-now-in-firefox/
lockPref("media.gmp-gmpopenh264.enabled",			false);
lockPref("media.gmp-manager.url",				"");

// PREF: Disable speculative pre-connections
// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_speculative-pre-connections
// https://bugzilla.mozilla.org/show_bug.cgi?id=814169
lockPref("network.http.speculative-parallel-limit",		0);

// PREF: Disable downloading homepage snippets/messages from Mozilla
// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_mozilla-content
// https://wiki.mozilla.org/Firefox/Projects/Firefox_Start/Snippet_Service
lockPref("browser.aboutHomeSnippets.updateUrl",		"");

// PREF: Never check updates for search engines
// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_auto-update-checking
lockPref("browser.search.update",				false);

/******************************************************************************
 * SECTION: HTTP                                                              *
 ******************************************************************************/

// PREF: Disallow NTLMv1
// https://bugzilla.mozilla.org/show_bug.cgi?id=828183
lockPref("network.negotiate-auth.allow-insecure-ntlm-v1",	false);
// it is still allowed through HTTPS. uncomment the following to disable it completely.
//lockPref("network.negotiate-auth.allow-insecure-ntlm-v1-https",		false);

// PREF: Enable CSP 1.1 script-nonce directive support
// https://bugzilla.mozilla.org/show_bug.cgi?id=855326
lockPref("security.csp.experimentalEnabled",			true);

// PREF: Enable Content Security Policy (CSP)
// https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy
// https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
lockPref("security.csp.enable",				true);

// PREF: Enable Subresource Integrity
// https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
// https://wiki.mozilla.org/Security/Subresource_Integrity
lockPref("security.sri.enable",				true);

// PREF: DNT HTTP header (disabled)
// https://www.mozilla.org/en-US/firefox/dnt/
// https://en.wikipedia.org/wiki/Do_not_track_header
// https://dnt-dashboard.mozilla.org
// https://github.com/pyllyukko/user.js/issues/11
// NOTICE: Do No Track must be enabled manually
//lockPref("privacy.donottrackheader.enabled",		true);

// PREF: Send a referer header with the target URI as the source
// https://bugzilla.mozilla.org/show_bug.cgi?id=822869
// https://github.com/pyllyukko/user.js/issues/227
// NOTICE: Spoofing referers breaks functionality on websites relying on authentic referer headers
// NOTICE: Spoofing referers breaks visualisation of 3rd-party sites on the Lightbeam addon
// NOTICE: Spoofing referers disables CSRF protection on some login pages not implementing origin-header/cookie+token based CSRF protection
// TODO: https://github.com/pyllyukko/user.js/issues/94, commented-out XOriginPolicy/XOriginTrimmingPolicy = 2 prefs
lockPref("network.http.referer.spoofSource",			true);

// PREF: Don't send referer headers when following links across different domains (disabled)
// https://github.com/pyllyukko/user.js/issues/227
// lockPref("network.http.referer.XOriginPolicy",		2);

// PREF: Accept Only 1st Party Cookies
// http://kb.mozillazine.org/Network.cookie.cookieBehavior#1
// NOTICE: Blocking 3rd-party cookies breaks a number of payment gateways
// CIS 2.5.1
lockPref("network.cookie.cookieBehavior",			1);

// PREF: Make sure that third-party cookies (if enabled) never persist beyond the session.
// https://feeding.cloud.geek.nz/posts/tweaking-cookies-for-privacy-in-firefox/
// http://kb.mozillazine.org/Network.cookie.thirdparty.sessionOnly
// https://developer.mozilla.org/en-US/docs/Cookies_Preferences_in_Mozilla#network.cookie.thirdparty.sessionOnly
lockPref("network.cookie.thirdparty.sessionOnly",		true);

// PREF: Spoof User-agent (disabled)
//lockPref("general.useragent.override",				"Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0");
//lockPref("general.appname.override",				"Netscape");
//lockPref("general.appversion.override",			"5.0 (Windows)");
//lockPref("general.platform.override",				"Win32");
//lockPref("general.oscpu.override",				"Windows NT 6.1");

/*******************************************************************************
 * SECTION: Caching                                                            *
 ******************************************************************************/

// PREF: Permanently enable private browsing mode
// https://support.mozilla.org/en-US/kb/Private-Browsing
// https://wiki.mozilla.org/PrivateBrowsing
// NOTICE: You can not view or inspect cookies when in private browsing: https://bugzilla.mozilla.org/show_bug.cgi?id=823941
// NOTICE: When Javascript is enabled, Websites can detect use of Private Browsing mode
// NOTICE: Private browsing breaks Kerberos authentication
// NOTICE: Disables "Containers" functionality (see below)
// NOTICE: "Always use private browsing mode" (browser.privatebrowsing.autostart) disables the possibility to use password manager: https://support.mozilla.org/en-US/kb/usernames-and-passwords-are-not-saved#w_private-browsing
lockPref("browser.privatebrowsing.autostart",			true);

// PREF: Do not download URLs for the offline cache
// http://kb.mozillazine.org/Browser.cache.offline.enable
lockPref("browser.cache.offline.enable",			false);

// PREF: Clear history when Firefox closes
// https://support.mozilla.org/en-US/kb/Clear%20Recent%20History#w_how-do-i-make-firefox-clear-my-history-automatically
// NOTICE: Installing user.js will remove your browsing history, caches and local storage.
// NOTICE: Installing user.js **will remove your saved passwords** (https://github.com/pyllyukko/user.js/issues/27)
// NOTICE: Clearing open windows on Firefox exit causes 2 windows to open when Firefox starts https://bugzilla.mozilla.org/show_bug.cgi?id=1334945
lockPref("privacy.sanitize.sanitizeOnShutdown",		true);
lockPref("privacy.clearOnShutdown.cache",			true);
lockPref("privacy.clearOnShutdown.cookies",			true);
lockPref("privacy.clearOnShutdown.downloads",			true);
lockPref("privacy.clearOnShutdown.formdata",			true);
lockPref("privacy.clearOnShutdown.history",			true);
lockPref("privacy.clearOnShutdown.offlineApps",		true);
lockPref("privacy.clearOnShutdown.sessions",			true);
lockPref("privacy.clearOnShutdown.openWindows",		true);

// PREF: Set time range to "Everything" as default in "Clear Recent History"
lockPref("privacy.sanitize.timeSpan",				0);

// PREF: Clear everything but "Site Preferences" in "Clear Recent History"
lockPref("privacy.cpd.offlineApps",				true);
lockPref("privacy.cpd.cache",					true);
lockPref("privacy.cpd.cookies",				true);
lockPref("privacy.cpd.downloads",				true);
lockPref("privacy.cpd.formdata",				true);
lockPref("privacy.cpd.history",				true);
lockPref("privacy.cpd.sessions",				true);

// PREF: Don't remember browsing history
lockPref("places.history.enabled",				false);

// PREF: Disable disk cache
// http://kb.mozillazine.org/Browser.cache.disk.enable
lockPref("browser.cache.disk.enable",				false);

// PREF: Disable memory cache (disabled)
// http://kb.mozillazine.org/Browser.cache.memory.enable
//lockPref("browser.cache.memory.enable",		false);

// PREF: Disable Caching of SSL Pages
// CIS Version 1.2.0 October 21st, 2011 2.5.8
// http://kb.mozillazine.org/Browser.cache.disk_cache_ssl
lockPref("browser.cache.disk_cache_ssl",			false);

// PREF: Disable download history
// CIS Version 1.2.0 October 21st, 2011 2.5.5
lockPref("browser.download.manager.retention",			0);

// PREF: Disable password manager
// CIS Version 1.2.0 October 21st, 2011 2.5.2
lockPref("signon.rememberSignons",				false);

// PREF: Disable form autofill, don't save information entered in web page forms and the Search Bar
lockPref("browser.formfill.enable",				false);

// PREF: Cookies expires at the end of the session (when the browser closes)
// http://kb.mozillazine.org/Network.cookie.lifetimePolicy#2
lockPref("network.cookie.lifetimePolicy",			2);

// PREF: Require manual intervention to autofill known username/passwords sign-in forms
// http://kb.mozillazine.org/Signon.autofillForms
// https://www.torproject.org/projects/torbrowser/design/#identifier-linkability
lockPref("signon.autofillForms",				false);

// PREF: Disable formless login capture
// https://bugzilla.mozilla.org/show_bug.cgi?id=1166947
lockPref("signon.formlessCapture.enabled",			false);

// PREF: When username/password autofill is enabled, still disable it on non-HTTPS sites
// https://hg.mozilla.org/integration/mozilla-inbound/rev/f0d146fe7317
lockPref("signon.autofillForms.http",				false);

// PREF: Show in-content login form warning UI for insecure login fields
// https://hg.mozilla.org/integration/mozilla-inbound/rev/f0d146fe7317
lockPref("security.insecure_field_warning.contextual.enabled", true);

// PREF: Disable the password manager for pages with autocomplete=off (disabled)
// https://bugzilla.mozilla.org/show_bug.cgi?id=956906
// OWASP ASVS V9.1
// Does not prevent any kind of auto-completion (see browser.formfill.enable, signon.autofillForms)
//lockPref("signon.storeWhenAutocompleteOff",			false);

// PREF: Delete Search and Form History
// CIS Version 1.2.0 October 21st, 2011 2.5.6
lockPref("browser.formfill.expire_days",			0);

// PREF: Clear SSL Form Session Data
// http://kb.mozillazine.org/Browser.sessionstore.privacy_level#2
// Store extra session data for unencrypted (non-HTTPS) sites only.
// CIS Version 1.2.0 October 21st, 2011 2.5.7
// NOTE: CIS says 1, we use 2
lockPref("browser.sessionstore.privacy_level",			2);

// PREF: Delete temporary files on exit
// https://bugzilla.mozilla.org/show_bug.cgi?id=238789
lockPref("browser.helperApps.deleteTempFileOnExit",		true);

// PREF: Do not create screenshots of visited pages (relates to the "new tab page" feature)
// https://support.mozilla.org/en-US/questions/973320
// https://developer.mozilla.org/en-US/docs/Mozilla/Preferences/Preference_reference/browser.pagethumbnails.capturing_disabled
lockPref("browser.pagethumbnails.capturing_disabled",		true);

// PREF: Don't fetch and permanently store favicons for Windows .URL shortcuts created by drag and drop
// NOTICE: .URL shortcut files will be created with a generic icon
// Favicons are stored as .ico files in $profile_dir\shortcutCache
lockPref("browser.shell.shortcutFavicons",					false);

// PREF: Disable bookmarks backups (default: 15)
// http://kb.mozillazine.org/Browser.bookmarks.max_backups
lockPref("browser.bookmarks.max_backups", 0);

/*******************************************************************************
 * SECTION: UI related                                                         *
 *******************************************************************************/

// PREF: Enable insecure password warnings (login forms in non-HTTPS pages)
// https://blog.mozilla.org/tanvi/2016/01/28/no-more-passwords-over-http-please/
// https://bugzilla.mozilla.org/show_bug.cgi?id=1319119
// https://bugzilla.mozilla.org/show_bug.cgi?id=1217156
lockPref("security.insecure_password.ui.enabled",		true);

// PREF: Disable right-click menu manipulation via JavaScript (disabled)
//lockPref("dom.event.contextmenu.enabled",		false);

// PREF: Disable "Are you sure you want to leave this page?" popups on page close
// https://support.mozilla.org/en-US/questions/1043508
// Does not prevent JS leaks of the page close event.
// https://developer.mozilla.org/en-US/docs/Web/Events/beforeunload
//lockPref("dom.disable_beforeunload",    true);

// PREF: Disable Downloading on Desktop
// CIS 2.3.2
lockPref("browser.download.folderList",			2);

// PREF: Always ask the user where to download
// https://developer.mozilla.org/en/Download_Manager_preferences (obsolete)
lockPref("browser.download.useDownloadDir",			false);

// PREF: Disable the "new tab page" feature and show a blank tab instead
// https://wiki.mozilla.org/Privacy/Reviews/New_Tab
// https://support.mozilla.org/en-US/kb/new-tab-page-show-hide-and-customize-top-sites#w_how-do-i-turn-the-new-tab-page-off
lockPref("browser.newtabpage.enabled",				false);
lockPref("browser.newtab.url",					"about:blank");

// PREF: Disable Activity Stream
// https://wiki.mozilla.org/Firefox/Activity_Stream
lockPref("browser.newtabpage.activity-stream.enabled",		false);

// PREF: Disable new tab tile ads & preload
// http://www.thewindowsclub.com/disable-remove-ad-tiles-from-firefox
// http://forums.mozillazine.org/viewtopic.php?p=13876331#p13876331
// https://wiki.mozilla.org/Tiles/Technical_Documentation#Ping
// https://gecko.readthedocs.org/en/latest/browser/browser/DirectoryLinksProvider.html#browser-newtabpage-directory-source
// https://gecko.readthedocs.org/en/latest/browser/browser/DirectoryLinksProvider.html#browser-newtabpage-directory-ping
// TODO: deprecated? not in DXR, some dead links
lockPref("browser.newtabpage.enhanced",			false);
lockPref("browser.newtab.preload",				false);
lockPref("browser.newtabpage.directory.ping",			"");
lockPref("browser.newtabpage.directory.source",		"data:text/plain,{}");

// PREF: Enable Auto Notification of Outdated Plugins (Firefox < 50)
// https://wiki.mozilla.org/Firefox3.6/Plugin_Update_Awareness_Security_Review
// CIS Version 1.2.0 October 21st, 2011 2.1.2
// https://hg.mozilla.org/mozilla-central/rev/304560
lockPref("plugins.update.notifyUser",				true);


// PREF: Force Punycode for Internationalized Domain Names
// http://kb.mozillazine.org/Network.IDN_show_punycode
// https://www.xudongz.com/blog/2017/idn-phishing/
// https://wiki.mozilla.org/IDN_Display_Algorithm
// https://en.wikipedia.org/wiki/IDN_homograph_attack
// https://www.mozilla.org/en-US/security/advisories/mfsa2017-02/
// CIS Mozilla Firefox 24 ESR v1.0.0 - 3.6
lockPref("network.IDN_show_punycode",				true);

// PREF: Disable inline autocomplete in URL bar
// http://kb.mozillazine.org/Inline_autocomplete
lockPref("browser.urlbar.autoFill",				false);
lockPref("browser.urlbar.autoFill.typed",			false);

// PREF: Disable CSS :visited selectors
// https://blog.mozilla.org/security/2010/03/31/plugging-the-css-history-leak/
// https://dbaron.org/mozilla/visited-privacy
lockPref("layout.css.visited_links_enabled",			false);

// PREF: Disable URL bar autocomplete and history/bookmarks suggestions dropdown
// http://kb.mozillazine.org/Disabling_autocomplete_-_Firefox#Firefox_3.5
lockPref("browser.urlbar.autocomplete.enabled",		false);

// PREF: Do not check if Firefox is the default browser
lockPref("browser.shell.checkDefaultBrowser",			false);

// PREF: When password manager is enabled, lock the password storage periodically
// CIS Version 1.2.0 October 21st, 2011 2.5.3 Disable Prompting for Credential Storage
lockPref("security.ask_for_password",				2);

// PREF: Lock the password storage every 1 minutes (default: 30)
lockPref("security.password_lifetime",				1);

// PREF: Display a notification bar when websites offer data for offline use
// http://kb.mozillazine.org/Browser.offline-apps.notify
lockPref("browser.offline-apps.notify",			true);

/******************************************************************************
 * SECTION: Cryptography                                                      *
 ******************************************************************************/

// PREF: Enable HSTS preload list (pre-set HSTS sites list provided by Mozilla)
// https://blog.mozilla.org/security/2012/11/01/preloading-hsts/
// https://wiki.mozilla.org/Privacy/Features/HSTS_Preload_List
// https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
lockPref("network.stricttransportsecurity.preloadlist",	true);

// PREF: Enable Online Certificate Status Protocol
// https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol
// https://www.imperialviolet.org/2014/04/19/revchecking.html
// https://www.maikel.pro/blog/current-state-certificate-revocation-crls-ocsp/
// https://wiki.mozilla.org/CA:RevocationPlan
// https://wiki.mozilla.org/CA:ImprovingRevocation
// https://wiki.mozilla.org/CA:OCSP-HardFail
// https://news.netcraft.com/archives/2014/04/24/certificate-revocation-why-browsers-remain-affected-by-heartbleed.html
// https://news.netcraft.com/archives/2013/04/16/certificate-revocation-and-the-performance-of-ocsp.html
// NOTICE: OCSP leaks your IP and domains you visit to the CA when OCSP Stapling is not available on visited host
// NOTICE: OCSP is vulnerable to replay attacks when nonce is not configured on the OCSP responder
// NOTICE: OCSP adds latency (performance)
// NOTICE: Short-lived certificates are not checked for revocation (security.pki.cert_short_lifetime_in_days, default:10)
// CIS Version 1.2.0 October 21st, 2011 2.2.4
lockPref("security.OCSP.enabled",				1);

// PREF: Enable OCSP Stapling support
// https://en.wikipedia.org/wiki/OCSP_stapling
// https://blog.mozilla.org/security/2013/07/29/ocsp-stapling-in-firefox/
// https://www.digitalocean.com/community/tutorials/how-to-configure-ocsp-stapling-on-apache-and-nginx
lockPref("security.ssl.enable_ocsp_stapling",			true);

// PREF: Enable OCSP Must-Staple support (Firefox >= 45)
// https://blog.mozilla.org/security/2015/11/23/improving-revocation-ocsp-must-staple-and-short-lived-certificates/
// https://www.entrust.com/ocsp-must-staple/
// https://github.com/schomery/privacy-settings/issues/40
// NOTICE: Firefox falls back on plain OCSP when must-staple is not configured on the host certificate
lockPref("security.ssl.enable_ocsp_must_staple",		true);

// PREF: Require a valid OCSP response for OCSP enabled certificates
// https://groups.google.com/forum/#!topic/mozilla.dev.security/n1G-N2-HTVA
// Disabling this will make OCSP bypassable by MitM attacks suppressing OCSP responses
// NOTICE: `security.OCSP.require` will make the connection fail when the OCSP responder is unavailable
// NOTICE: `security.OCSP.require` is known to break browsing on some [captive portals](https://en.wikipedia.org/wiki/Captive_portal)
lockPref("security.OCSP.require",				true);

// PREF: Disable TLS Session Tickets
// https://www.blackhat.com/us-13/briefings.html#NextGen
// https://media.blackhat.com/us-13/US-13-Daigniere-TLS-Secrets-Slides.pdf
// https://media.blackhat.com/us-13/US-13-Daigniere-TLS-Secrets-WP.pdf
// https://bugzilla.mozilla.org/show_bug.cgi?id=917049
// https://bugzilla.mozilla.org/show_bug.cgi?id=967977
lockPref("security.ssl.disable_session_identifiers",		true);

// PREF: Only allow TLS 1.[0-3]
// http://kb.mozillazine.org/Security.tls.version.*
// 1 = TLS 1.0 is the minimum required / maximum supported encryption protocol. (This is the current default for the maximum supported version.)
// 2 = TLS 1.1 is the minimum required / maximum supported encryption protocol.
lockPref("security.tls.version.min",				1);
lockPref("security.tls.version.max",				4);

// PREF: Disable insecure TLS version fallback
// https://bugzilla.mozilla.org/show_bug.cgi?id=1084025
// https://github.com/pyllyukko/user.js/pull/206#issuecomment-280229645
lockPref("security.tls.version.fallback-limit",		3);

// PREF: Enfore Public Key Pinning
// https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning
// https://wiki.mozilla.org/SecurityEngineering/Public_Key_Pinning
// "2. Strict. Pinning is always enforced."
lockPref("security.cert_pinning.enforcement_level",		2);

// PREF: Disallow SHA-1
// https://bugzilla.mozilla.org/show_bug.cgi?id=1302140
// https://shattered.io/
lockPref("security.pki.sha1_enforcement_level",		1);

// PREF: Warn the user when server doesn't support RFC 5746 ("safe" renegotiation)
// https://wiki.mozilla.org/Security:Renegotiation#security.ssl.treat_unsafe_negotiation_as_broken
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-3555
lockPref("security.ssl.treat_unsafe_negotiation_as_broken",	true);

// PREF: Disallow connection to servers not supporting safe renegotiation (disabled)
// https://wiki.mozilla.org/Security:Renegotiation#security.ssl.require_safe_negotiation
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-3555
// TODO: `security.ssl.require_safe_negotiation` is more secure but makes browsing next to impossible (2012-2014-... - `ssl_error_unsafe_negotiation` errors), so is left disabled
//lockPref("security.ssl.require_safe_negotiation",		true);

// PREF: Disable automatic reporting of TLS connection errors
// https://support.mozilla.org/en-US/kb/certificate-pinning-reports
// we could also disable security.ssl.errorReporting.enabled, but I think it's
// good to leave the option to report potentially malicious sites if the user
// chooses to do so.
// you can test this at https://pinningtest.appspot.com/
lockPref("security.ssl.errorReporting.automatic",		false);

// PREF: Pre-populate the current URL but do not pre-fetch the certificate in the "Add Security Exception" dialog
// http://kb.mozillazine.org/Browser.ssl_override_behavior
// https://github.com/pyllyukko/user.js/issues/210
lockPref("browser.ssl_override_behavior",			1);

/******************************************************************************
 * SECTION: Cipher suites                                                     *
 ******************************************************************************/

// PREF: Disable null ciphers
lockPref("security.ssl3.rsa_null_sha",				false);
lockPref("security.ssl3.rsa_null_md5",				false);
lockPref("security.ssl3.ecdhe_rsa_null_sha",			false);
lockPref("security.ssl3.ecdhe_ecdsa_null_sha",			false);
lockPref("security.ssl3.ecdh_rsa_null_sha",			false);
lockPref("security.ssl3.ecdh_ecdsa_null_sha",			false);

// PREF: Disable SEED cipher
// https://en.wikipedia.org/wiki/SEED
lockPref("security.ssl3.rsa_seed_sha",				false);

// PREF: Disable 40/56/128-bit ciphers
// 40-bit ciphers
lockPref("security.ssl3.rsa_rc4_40_md5",			false);
lockPref("security.ssl3.rsa_rc2_40_md5",			false);
// 56-bit ciphers
lockPref("security.ssl3.rsa_1024_rc4_56_sha",			false);
// 128-bit ciphers
lockPref("security.ssl3.rsa_camellia_128_sha",			false);
lockPref("security.ssl3.ecdhe_rsa_aes_128_sha",		false);
lockPref("security.ssl3.ecdhe_ecdsa_aes_128_sha",		false);
lockPref("security.ssl3.ecdh_rsa_aes_128_sha",			false);
lockPref("security.ssl3.ecdh_ecdsa_aes_128_sha",		false);
lockPref("security.ssl3.dhe_rsa_camellia_128_sha",		false);
lockPref("security.ssl3.dhe_rsa_aes_128_sha",			false);

// PREF: Disable RC4
// https://developer.mozilla.org/en-US/Firefox/Releases/38#Security
// https://bugzilla.mozilla.org/show_bug.cgi?id=1138882
// https://rc4.io/
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2566
lockPref("security.ssl3.ecdh_ecdsa_rc4_128_sha",		false);
lockPref("security.ssl3.ecdh_rsa_rc4_128_sha",			false);
lockPref("security.ssl3.ecdhe_ecdsa_rc4_128_sha",		false);
lockPref("security.ssl3.ecdhe_rsa_rc4_128_sha",		false);
lockPref("security.ssl3.rsa_rc4_128_md5",			false);
lockPref("security.ssl3.rsa_rc4_128_sha",			false);
lockPref("security.tls.unrestricted_rc4_fallback",		false);

// PREF: Disable 3DES (effective key size is < 128)
// https://en.wikipedia.org/wiki/3des#Security
// http://en.citizendium.org/wiki/Meet-in-the-middle_attack
// http://www-archive.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
lockPref("security.ssl3.dhe_dss_des_ede3_sha",			false);
lockPref("security.ssl3.dhe_rsa_des_ede3_sha",			false);
lockPref("security.ssl3.ecdh_ecdsa_des_ede3_sha",		false);
lockPref("security.ssl3.ecdh_rsa_des_ede3_sha",		false);
lockPref("security.ssl3.ecdhe_ecdsa_des_ede3_sha",		false);
lockPref("security.ssl3.ecdhe_rsa_des_ede3_sha",		false);
lockPref("security.ssl3.rsa_des_ede3_sha",			false);
lockPref("security.ssl3.rsa_fips_des_ede3_sha",		false);

// PREF: Disable ciphers with ECDH (non-ephemeral)
lockPref("security.ssl3.ecdh_rsa_aes_256_sha",			false);
lockPref("security.ssl3.ecdh_ecdsa_aes_256_sha",		false);

// PREF: Disable 256 bits ciphers without PFS
lockPref("security.ssl3.rsa_camellia_256_sha",			false);

// PREF: Enable ciphers with ECDHE and key size > 128bits
lockPref("security.ssl3.ecdhe_rsa_aes_256_sha",		true); // 0xc014
lockPref("security.ssl3.ecdhe_ecdsa_aes_256_sha",		true); // 0xc00a

// PREF: Enable GCM ciphers (TLSv1.2 only)
// https://en.wikipedia.org/wiki/Galois/Counter_Mode
lockPref("security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256",	true); // 0xc02b
lockPref("security.ssl3.ecdhe_rsa_aes_128_gcm_sha256",		true); // 0xc02f

// PREF: Enable ChaCha20 and Poly1305 (Firefox >= 47)
// https://www.mozilla.org/en-US/firefox/47.0/releasenotes/
// https://tools.ietf.org/html/rfc7905
// https://bugzilla.mozilla.org/show_bug.cgi?id=917571
// https://bugzilla.mozilla.org/show_bug.cgi?id=1247860
// https://cr.yp.to/chacha.html
lockPref("security.ssl3.ecdhe_ecdsa_chacha20_poly1305_sha256",	true);
lockPref("security.ssl3.ecdhe_rsa_chacha20_poly1305_sha256",	true);

// PREF: Disable ciphers susceptible to the logjam attack
// https://weakdh.org/
lockPref("security.ssl3.dhe_rsa_camellia_256_sha",		false);
lockPref("security.ssl3.dhe_rsa_aes_256_sha",			false);

// PREF: Disable ciphers with DSA (max 1024 bits)
lockPref("security.ssl3.dhe_dss_aes_128_sha",			false);
lockPref("security.ssl3.dhe_dss_aes_256_sha",			false);
lockPref("security.ssl3.dhe_dss_camellia_128_sha",		false);
lockPref("security.ssl3.dhe_dss_camellia_256_sha",		false);

// PREF: Fallbacks due compatibility reasons
lockPref("security.ssl3.rsa_aes_256_sha",			true); // 0x35
lockPref("security.ssl3.rsa_aes_128_sha",			true); // 0x2f
