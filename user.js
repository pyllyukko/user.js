/******************************************************************************
 * user.js                                                                    *
 * https://github.com/pyllyukko/user.js										  *
 * 																			  *
 * This is the Firefox own user.js which stores the changed about:config      *
 * settings     															  *
 ******************************************************************************/



/******************************************************************************
 * HTML5 / APIs / DOM related                                                 *
 *                                                                            *
 ******************************************************************************/

// Description: Disable Location-Aware Browsing
// See: 		http://www.mozilla.org/en-US/firefox/geolocation/
user_pref("geo.enabled",		false);


// Description: 
// See: 		http://kb.mozillazine.org/Dom.storage.enabled
// Also: 		http://dev.w3.org/html5/webstorage/#dom-localstorage
// You can also see this with Panopticlick's "DOM localStorage"
//user_pref("dom.storage.enabled",		false);


// Description: Hide your internal IP
// See:			http://net.ipcalf.com/
user_pref("media.peerconnection.enabled",		false);


// Description: getUserMedia
// See:			https://wiki.mozilla.org/Media/getUserMedia
// See:			https://developer.mozilla.org/en-US/docs/Web/API/Navigator
user_pref("media.navigator.enabled",		false);


// Description: Disable BatteryManager 
// See:			https://developer.mozilla.org/en-US/docs/Web/API/BatteryManager
user_pref("dom.battery.enabled",		false);


// Description: Disable Beacon's 
// See:			https://developer.mozilla.org/en-US/docs/Web/API/navigator.sendBeacon
user_pref("beacon.enabled",		false);


// Description: Disable DOM Clipboard-Event logging
// See:			https://developer.mozilla.org/en-US/docs/Mozilla/Preferences/Preference_reference/dom.event.clipboardevents.enabled
user_pref("dom.event.clipboardevents.enabled",		false);


// Description: 
// https://wiki.mozilla.org/Security/Reviews/Firefox/NavigationTimingAPI
user_pref("dom.enable_performance",		false);


// Description: Disable getUserMedia screen sharing
// See:			https://mozilla.github.io/webrtc-landing/gum_test.html
user_pref("media.getusermedia.screensharing.enabled",		false);


// Description: Disable internal sensor API
// See:			https://wiki.mozilla.org/Sensor_API
user_pref("device.sensors.enabled",		false);


// Description: Disabled external browser pings
// See: 		http://kb.mozillazine.org/Browser.send_pings
user_pref("browser.send_pings"
// this shouldn't have any effect, since we block pings altogether, but we'll set it anyway.
// http://kb.mozillazine.org/Browser.send_pings.require_same_host
user_pref("browser.send_pings.require_same_host",		true);


// Description: Disable external Gamepads
// See:			http://www.w3.org/TR/gamepad/
user_pref("dom.gamepad.enabled",		false);


// Description: Disable WebGL
// See: 		http://www.contextis.com/resources/blog/webgl-new-dimension-browser-exploitation/
// Note:		Can also be controlled via NoScript
user_pref("webgl.disabled",		true);
// Description: Disable internal pdf WebGL rendering
//user_pref("pdfjs.enableWebGL",					false);



/******************************************************************************
 * Miscellaneous                                                              *
 *                                                                            *
 ******************************************************************************/

// Description: Default search engine, set to a more secure one DuckDuckGo
// See: 		https://support.mozilla.org/questions/1034136
//user_pref("browser.search.defaultenginename",			"DuckDcukGo");


// Description: Display an error message indicating the entered information is not a valid
// URL instead of asking from Google.
// See:			http://kb.mozillazine.org/Keyword.enabled#Caveats
user_pref("keyword.enabled",					false);


// Description: Don't try to guess where I'm trying to go!!! e.g.: "http://foo" -> "http://(prefix)foo(suffix)"
// See:			http://www-archive.mozilla.org/docs/end-user/domain-guessing.html
user_pref("browser.fixup.alternate.enabled",		false);


// Description: Allow remote DNS resolvers
// See: https://trac.torproject.org/projects/tor/wiki/doc/TorifyHOWTO/WebBrowsers
user_pref("network.proxy.socks_remote_dns",		true);


// Description: The default in Firefox for Linux/Windows is to use the own system proxy settings
// See:			http://kb.mozillazine.org/Network.proxy.type
//user_pref("network.proxy.type", 0);


//Description: Mixed content stuff
//See:		https://developer.mozilla.org/en-US/docs/Site_Compatibility_for_Firefox_23#Non-SSL_contents_on_SSL_pages_are_blocked_by_default
//Also:		https://blog.mozilla.org/tanvi/2013/04/10/mixed-content-blocking-enabled-in-firefox-23/
user_pref("security.mixed_content.block_display_content",		true);


// Description: CIS 2.7.4 Disable Scripting of Plugins by JavaScript
// See:			http://forums.mozillazine.org/viewtopic.php?f=7&t=153889
user_pref("security.xpconnect.plugin.unrestricted",		false);


// Description: CIS Mozilla Firefox 24 ESR v1.0.0 - 3.8 Set File URI Origin Policy
// See:			http://kb.mozillazine.org/Security.fileuri.strict_origin_policy
user_pref("security.fileuri.strict_origin_policy",		false);


// Description: Disables the internal asm.js-Compiler 
// See:			http://asmjs.org/
// Also: 		https://www.mozilla.org/en-US/security/advisories/mfsa2015-29/
// Also:		https://www.mozilla.org/en-US/security/advisories/mfsa2015-50/
// Also:		https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-2712
user_pref("javascript.options.asmjs",				false);


// Description: 
// See: 		https://wiki.mozilla.org/SVGOpenTypeFonts
// Note: This may break some external Addons that use such Font's
user_pref("gfx.font_rendering.opentype_svg.enabled",		false);



/******************************************************************************
 * Extensions / Plugins                                                       *
 *                                                                            *
 ******************************************************************************/

// Description: Disables Adobe Flash Player plugin which will be never activated by default
// See:			https://bugzilla.mozilla.org/show_bug.cgi?id=866390	
user_pref("plugin.state.flash",					0);


// Description: Disables the addon blacklist, since this wants to connect to a database
// See:			http://kb.mozillazine.org/Extensions.blocklist.enabled
user_pref("extensions.blocklist.enabled",			false);



/******************************************************************************
 * Features / Components                                                      *
 *                                                                            *
 ******************************************************************************/

// Description: Disables Firefox's tracking protection
// See:			https://wiki.mozilla.org/Polaris#Tracking_protection
// See:			https://support.mozilla.org/en-US/kb/tracking-protection-firefox
// TODO: are these two the same?
user_pref("privacy.trackingprotection.enabled",		false);


// Description: Disable the built-in PDF viewer
// See: 		https://support.mozilla.org/questions/950988
//user_pref("pdfjs.disabled",				true);


// Description: Disable sending of the health report
// See:			https://support.mozilla.org/en-US/kb/firefox-health-report-understand-your-browser-perf
user_pref("datareporting.healthreport.uploadEnabled",	false);


// Description: Disable new tab tile ads & preload
// See:			http://www.thewindowsclub.com/disable-remove-ad-tiles-from-firefox
// See:			http://forums.mozillazine.org/viewtopic.php?p=13876331#p13876331
user_pref("browser.newtabpage.enhanced",			false);
user_pref("browser.newtab.preload",				false);


// Description: Disable sending internal heartbeat
// See: 		https://wiki.mozilla.org/Advocacy/heartbeat
user_pref("browser.selfsupport.url",				"");


// Description: CIS 2.3.4 Block Reported Web Forgeries - disables the safebrowsing mechanism
// See:			http://kb.mozillazine.org/Browser.safebrowsing.enabled
// See:			http://kb.mozillazine.org/Safe_browsing
user_pref("browser.safebrowsing.enabled",		false);


// Description: CIS 2.3.5 Block Reported Attack Sites
// See:			http://kb.mozillazine.org/Browser.safebrowsing.malware.enabled
user_pref("browser.safebrowsing.malware.enabled",	true);


/******************************************************************************
 * Automatic connections                                                      *
 *                                                                            *
 ******************************************************************************/

// Description: Disable link pre-fetching
// See:			http://kb.mozillazine.org/Network.prefetch-next
// Also:		https://developer.mozilla.org/en-US/docs/Web/HTTP/Link_prefetching_FAQ#Is_there_a_preference_to_disable_link_prefetching.3F
user_pref("network.prefetch-next",		false);


// Description: Disables the own prefetch mechanism (also for https)
// See: 		http://kb.mozillazine.org/Network.dns.disablePrefetch
// Also:		https://developer.mozilla.org/en-US/docs/Web/HTTP/Controlling_DNS_prefetching
user_pref("network.dns.disablePrefetch",			true);
user_pref("network.dns.disablePrefetchFromHTTPS",		true);


// Description: Disable the internal GeoIP tag, in future builds Mozillas own localisations url can be used
// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_geolocation-for-default-search-engine
user_pref("browser.search.geoip.url",		"");


// Description: Disables the media.gmp update url 
// See: 		
user_pref("media.gmp-manager.url", "");


// Description: Disable the predictor 
// See: 		https://wiki.mozilla.org/Privacy/Reviews/Necko
user_pref("network.predictor.enabled",				false);


// Description: Disable the search suggestion 
// See: 		http://kb.mozillazine.org/Browser.search.suggest.enabled
user_pref("browser.search.suggest.enabled",			false);

<<<<<<< HEAD
=======
// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_media-capabilities
// http://andreasgal.com/2014/10/14/openh264-now-in-firefox/
user_pref("media.gmp-gmpopenh264.enabled",			false);
user_pref("media.gmp-manager.url",				"");
>>>>>>> ab0951d5e00f844912b36bb38bb80c642f7f76df

// Description: No pre-calculated auto-network connections
// See: 		https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_speculative-pre-connections
user_pref("network.http.speculative-parallel-limit",		0);


// Description: 
// See: 		https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_mozilla-content
user_pref("browser.aboutHomeSnippets.updateUrl"			"");


// Description: Disables automatically search updates to prevent some connections 
// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_auto-update-checking
user_pref("browser.search.update"				false);

/******************************************************************************
 * HTTP / Headers                                                             *
 *                                                                            *
 ******************************************************************************/

// Description: Enable experimental mcsp checking 
// See:			https://bugzilla.mozilla.org/show_bug.cgi?id=855326
user_pref("security.csp.experimentalEnabled",			true);


// Description: DNT HTTP header
// See: 		http://dnt.mozilla.org/
// Also:		https://en.wikipedia.org/wiki/Do_not_track_header
// Also: 		https://dnt-dashboard.mozilla.org
// Also: 		https://github.com/pyllyukko/user.js/issues/11
// Note:		Enabling the DNT header can possible makes it easier to fingerprint your Browser
//user_pref("privacy.donottrackheader.enabled",			true);


// Description: Referrer headers 
// See:			http://kb.mozillazine.org/Network.http.sendRefererHeader#0
// Also:		https://bugzilla.mozilla.org/show_bug.cgi?id=822869
// Also:		Send a referrer header with the target URI as the source
// Note: 		These settings can be controlled via NoScript, Random Agent Spoofer and Firefox via options
user_pref("network.http.sendRefererHeader",			1);
user_pref("network.http.referer.spoofSource",			true);
// CIS Version 1.2.0 October 21st, 2011 2.4.3 Disable Referrer from an SSL Website
user_pref("network.http.sendSecureXSiteReferrer",		false);


// Description: CIS 2.5.1 Accept only 1st Party Cookies, change to 2 to not allow any Cookies by default 
// See: 		http://kb.mozillazine.org/Network.cookie.cookieBehavior#1
user_pref("network.cookie.cookieBehavior",		1);

// Description: Change the default user-agent
// See:			
// Note:		Some addons like uMatrix, RAS, NoScript and others can change these automatically after xyz minutes periodically 
//user_pref("general.useragent.override", "Mozilla/5.0 (Windows NT 6.1; rv:31.0) Gecko/20100101 Firefox/31.0");


/******************************************************************************
 * Caching                                                                    *
 *                                                                            *
 ******************************************************************************/

// Description: 
// See: 		http://kb.mozillazine.org/Browser.cache.offline.enable
user_pref("browser.cache.offline.enable",		false);

// Description: Always use private browsing by default 
// See: 		https://support.mozilla.org/en-US/kb/Private-Browsing
// See: 		https://wiki.mozilla.org/PrivateBrowsing
// Note:		Not all addons ma work correct under the private browsing mode
user_pref("browser.privatebrowsing.autostart",		true);
// Ghostery addon private mode 
user_pref("extensions.ghostery.privateBrowsing",	true);


// Description: Clear and clean the history when FF closes
// See:		https://support.mozilla.org/en-US/kb/Clear%20Recent%20History#w_how-do-i-make-firefox-clear-my-history-automatically
// Note:		Cache, Cookies, Downloads, Form fill data, Browsing History, Offline Apps, Passwords, Browsing Sessions and Site Settings 
user_pref("privacy.sanitize.sanitizeOnShutdown",	true);
user_pref("privacy.clearOnShutdown.cache",		true);
user_pref("privacy.clearOnShutdown.cookies",		true);
user_pref("privacy.clearOnShutdown.downloads",		true);
user_pref("privacy.clearOnShutdown.formdata",		true);
user_pref("privacy.clearOnShutdown.history",		true);
user_pref("privacy.clearOnShutdown.offlineApps",	true);
user_pref("privacy.clearOnShutdown.passwords",		true);
user_pref("privacy.clearOnShutdown.sessions",		true);
//user_pref("privacy.clearOnShutdown.siteSettings",	true);


// Description: Don't remember browsing history
// See:			
user_pref("places.history.enabled",			false);


// Description: The cookie expires at the end of the session (when the browser closes)
// See:			http://kb.mozillazine.org/Network.cookie.lifetimePolicy#2
user_pref("network.cookie.lifetimePolicy",		2);


// Description: 
// See:			http://kb.mozillazine.org/Browser.cache.disk.enable
user_pref("browser.cache.disk.enable",			false);


// Description: 
// See:			http://kb.mozillazine.org/Browser.cache.memory.enable
//user_pref("browser.cache.memory.enable",		false);


// Description: CIS Version 1.2.0 October 21st, 2011 2.5.8 Disable Caching of SSL Pages
// See:			http://kb.mozillazine.org/Browser.cache.disk_cache_ssl
user_pref("browser.cache.disk_cache_ssl",		false);


// Description: CIS Version 1.2.0 October 21st, 2011 2.5.2 Disallow Credential Storage
// See:			
user_pref("signon.rememberSignons",			false);


// Description: CIS Version 1.2.0 October 21st, 2011 2.5.6 Delete Search and Form History
// See:			
user_pref("browser.formfill.enable",			false);
user_pref("browser.formfill.expire_days",		0);

// CIS Version 1.2.0 October 21st, 2011 2.5.7 Clear SSL Form Session Data
// http://kb.mozillazine.org/Browser.sessionstore.privacy_level#2
// Store extra session data for unencrypted (non-HTTPS) sites only.
// NOTE: CIS says 1, we use 2
user_pref("browser.sessionstore.privacy_level",		2);
//user_pref("browser.sessionstore.privacy_level_deferred",		1);



/******************************************************************************
 * UI related                                                                 *
 *                                                                            *
 ******************************************************************************/

// Description: Webpages will not be able to affect the right-click menu
// See:			
//user_pref("dom.event.contextmenu.enabled",			false);


// Description: CIS 2.3.2 Disable Downloading on Desktop
// See:			
// Note: 		0 allow the Desktop Download
user_pref("browser.download.folderList",		2);


// Description: Always ask the user where to download
// See:			https://developer.mozilla.org/en/Download_Manager_preferences
user_pref("browser.download.useDownloadDir",		false);


// Description: 
// See:			https://wiki.mozilla.org/Privacy/Reviews/New_Tab
user_pref("browser.newtabpage.enabled",			false);


// Description: CIS Version 1.2.0 October 21st, 2011 2.1.2 Enable Auto Notification of Outdated Plugins
// See:			https://wiki.mozilla.org/Firefox3.6/Plugin_Update_Awareness_Security_Review
user_pref("plugins.update.notifyUser",			true);


// Description: CIS Mozilla Firefox 24 ESR v1.0.0 - 3.6 Enable IDN Show Punycode
// See:			http://kb.mozillazine.org/Network.IDN_show_punycode
user_pref("network.IDN_show_punycode",			true);


// Description: 
// See:			http://kb.mozillazine.org/About:config_entries#Browser
// Also:		http://kb.mozillazine.org/Inline_autocomplete
user_pref("browser.urlbar.autoFill",			false);
user_pref("browser.urlbar.autoFill.typed",		false);


// Description: Setting the preference to 0 effectively disables the Location Bar drop-down entirely
// See:			http://www.labnol.org/software/browsers/prevent-firefox-showing-bookmarks-address-location-bar/3636/
// Also:		http://kb.mozillazine.org/Browser.urlbar.maxRichResults
user_pref("browser.urlbar.maxRichResults",		0);


// Description: 
// See:			https://blog.mozilla.org/security/2010/03/31/plugging-the-css-history-leak/
// See:			http://dbaron.org/mozilla/visited-privacy
user_pref("layout.css.visited_links_enabled",		false);


// Description: 
// See:			http://kb.mozillazine.org/Disabling_autocomplete_-_Firefox#Firefox_3.5
user_pref("browser.urlbar.autocomplete.enabled",	false);

// Description: 
// See:			http://kb.mozillazine.org/Signon.autofillForms
// Also:		https://www.torproject.org/projects/torbrowser/design/#identifier-linkability
user_pref("signon.autofillForms",			false);



/******************************************************************************
 * TLS / HTTPS / OCSP related stuff                                           *
 *                                                                            *
 ******************************************************************************/

// Description: CIS Version 1.2.0 October 21st, 2011 2.2.4 Enable Online Certificate Status Protocol
// See:			
user_pref("security.OCSP.enabled",			0);


// Description: Disable SSLv3 (CVE-2014-3566)
// See:			
user_pref("security.enable_ssl3",			false);


// Description: Cert pinning - 2. Strict. Pinning is always enforced
// See:			https://wiki.mozilla.org/SecurityEngineering/Public_Key_Pinning#How_to_use_pinning
user_pref("security.cert_pinning.enforcement_level",	2);


// Description: 
// See:			https://wiki.mozilla.org/Security:Renegotiation#security.ssl.treat_unsafe_negotiation_as_broken
// Note:		CVE-2009-3555
user_pref("security.ssl.treat_unsafe_negotiation_as_broken",	true);


// Description: 
// See:			https://wiki.mozilla.org/Security:Renegotiation#security.ssl.require_safe_negotiation
// Note:		CVE-2009-3555
user_pref("security.ssl.require_safe_negotiation",	true);


//
// Be careful with the following settings, this may leak some data 
//

// Description: 
// See:		 	https://blog.mozilla.org/security/2013/07/29/ocsp-stapling-in-firefox/
user_pref("security.ssl.enable_ocsp_stapling",		true);


// Description: Require certificate revocation check through OCSP protocol
// See:			
// Note:		 See above warning !
user_pref("security.OCSP.require",			true);



/******************************************************************************
 * CIPHERS                                                                    *
 *                                                                            *
 * you can debug the SSL handshake with tshark: tshark -t ad -n -i wlan0 -T text -V -R ssl.handshake
 ******************************************************************************/

// Disable null ciphers
// Note:		All removed or already default at maximum due security reasons! 
user_pref("security.ssl3.rsa_null_sha",		false);
user_pref("security.ssl3.rsa_null_md5",		false);
user_pref("security.ssl3.ecdhe_rsa_null_sha",	false);
user_pref("security.ssl3.ecdhe_ecdsa_null_sha",	false);
user_pref("security.ssl3.ecdh_rsa_null_sha",	false);
user_pref("security.ssl3.ecdh_ecdsa_null_sha",	false);

// 40 bits...
user_pref("security.ssl3.rsa_rc4_40_md5",	false);
user_pref("security.ssl3.rsa_rc2_40_md5",	false);

// 56 bits
user_pref("security.ssl3.rsa_1024_rc4_56_sha",	false);

// GCM... yes please!
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256",	true);
user_pref("security.ssl3.ecdhe_rsa_aes_128_gcm_sha256",		true);

/* fallbacks
 */
user_pref("security.ssl3.rsa_aes_256_sha",		true);
user_pref("security.ssl3.rsa_aes_128_sha",		true);

// ciphers with ECDHE and > 128bits
user_pref("security.ssl3.ecdhe_rsa_aes_256_sha",	true);
user_pref("security.ssl3.ecdhe_ecdsa_aes_256_sha",	true);


// Note:		New settings - changed 
/* SEED
 * https://en.wikipedia.org/wiki/SEED
 */
user_pref("security.ssl3.rsa_seed_sha",		false);

// 128 bits
user_pref("security.ssl3.rsa_camellia_128_sha",		false);
//user_pref("security.ssl3.rsa_aes_128_sha",		false);
user_pref("security.ssl3.ecdhe_rsa_aes_128_sha",	false);
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_sha",	false);
user_pref("security.ssl3.ecdh_rsa_aes_128_sha",		false);
user_pref("security.ssl3.ecdh_ecdsa_aes_128_sha",	false);
user_pref("security.ssl3.dhe_rsa_camellia_128_sha",	false);
user_pref("security.ssl3.dhe_rsa_aes_128_sha",		false);

// RC4 (CVE-2013-2566)
user_pref("security.ssl3.ecdh_ecdsa_rc4_128_sha",	false);
user_pref("security.ssl3.ecdh_rsa_rc4_128_sha",		false);
user_pref("security.ssl3.ecdhe_ecdsa_rc4_128_sha",	false);
user_pref("security.ssl3.ecdhe_rsa_rc4_128_sha",	false);
user_pref("security.ssl3.rsa_rc4_128_md5",		false);
user_pref("security.ssl3.rsa_rc4_128_sha",		false);

/*
 * 3DES -> false because effective key size < 128
 *
 *   https://en.wikipedia.org/wiki/3des#Security
 *   http://en.citizendium.org/wiki/Meet-in-the-middle_attack
 *
 * see also: http://www-archive.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
 */
user_pref("security.ssl3.dhe_dss_des_ede3_sha",		false);
user_pref("security.ssl3.dhe_rsa_des_ede3_sha",		false);
user_pref("security.ssl3.ecdh_ecdsa_des_ede3_sha",	false);
user_pref("security.ssl3.ecdh_rsa_des_ede3_sha",	false);
user_pref("security.ssl3.ecdhe_ecdsa_des_ede3_sha",	false);
user_pref("security.ssl3.ecdhe_rsa_des_ede3_sha",	false);
user_pref("security.ssl3.rsa_des_ede3_sha",		false);
user_pref("security.ssl3.rsa_fips_des_ede3_sha",	false);

// ciphers with ECDH (without /e$/)
user_pref("security.ssl3.ecdh_rsa_des_ede3_sha",	false);
user_pref("security.ssl3.ecdh_rsa_aes_256_sha",		false);
user_pref("security.ssl3.ecdh_ecdsa_des_ede3_sha",	false);
user_pref("security.ssl3.ecdh_ecdsa_aes_256_sha",	false);

// 256 bits without PFS
user_pref("security.ssl3.rsa_camellia_256_sha",		false);
user_pref("security.ssl3.rsa_aes_256_sha",		false);


// susceptible to the logjam attack – https://weakdh.org/
user_pref("security.ssl3.dhe_rsa_camellia_256_sha",	false);
user_pref("security.ssl3.dhe_rsa_aes_256_sha",		false);

// ciphers with DSA (max 1024 bits)
user_pref("security.ssl3.dhe_dss_aes_128_sha",		false);
user_pref("security.ssl3.dhe_dss_aes_256_sha",		false);
user_pref("security.ssl3.dhe_dss_camellia_128_sha",	false);
user_pref("security.ssl3.dhe_dss_camellia_256_sha",	false);
user_pref("security.ssl3.dhe_dss_des_ede3_sha",		false);



/******************************************************************************
 * Deprecated/Obsolete                                                         *
 * Note: Only use these settings with older FF releases!   					   * 
 * Ensure that you always use the latest Firefox release to stay maximum secure*
 ******************************************************************************/

 // See:		https://secure.wikimedia.org/wikibooks/en/wiki/Grsecurity/Application-specific_Settings#Firefox_.28or_Iceweasel_in_Debian.29
// Note: 	Doesn't exists anymore since FF 38.x
//user_pref("javascript.options.methodjit.chrome",		false);
//user_pref("javascript.options.methodjit.content",		false);


// Description: Disable WebTelephony 
// See:			https://wiki.mozilla.org/WebAPI/Security/WebTelephony
// Note:		Default false since FF 38.x
//user_pref("dom.telephony.enabled",		false);


// Description: Disable Speech recognition
// See: 		https://dvcs.w3.org/hg/speech-api/raw-file/tip/speechapi.html
// Also:		https://wiki.mozilla.org/HTML5_Speech_API
//user_pref("media.webspeech.recognition.enable",		false);


// https://developer.mozilla.org/en-US/docs/IndexedDB
// https://wiki.mozilla.org/Security/Reviews/Firefox4/IndexedDB_Security_Review
// TODO: find out why html5test still reports this as available
// NOTE: this is enabled for now, as disabling this seems to break some plugins.
//       see: http://forums.mozillazine.org/viewtopic.php?p=13842047#p13842047
//user_pref("dom.indexedDB.enabled",				true);

// TODO: "Access Your Location" "Maintain Offline Storage" "Show Notifications"


// Description: Disable virtual reality devices
// See: 		https://developer.mozilla.org/en-US/Firefox/Releases/36#Interfaces.2FAPIs.2FDOM
// Note:		Default false since Firefox 38.x
//user_pref("dom.vr.enabled",		false);


// Description: Disable Clipboard autocopy feature
// See:		http://kb.mozillazine.org/Clipboard.autocopy
// Note: 	Default false since Firefox 38.x
//user_pref("clipboard.autocopy",					false);


/* Mixed content stuff
 *   - https://developer.mozilla.org/en-US/docs/Site_Compatibility_for_Firefox_23#Non-SSL_contents_on_SSL_pages_are_blocked_by_default
 *   - https://blog.mozilla.org/tanvi/2013/04/10/mixed-content-blocking-enabled-in-firefox-23/
 */
//user_pref("security.mixed_content.block_active_content",		true);


// Description: CIS Mozilla Firefox 24 ESR v1.0.0 - 3.7 Disable JAR from opening Unsafe File Types
// See: 		http://kb.mozillazine.org/Network.jar.open-unsafe-types
// user_pref("network.jar.open-unsafe-types",			false);


// Description: CIS 2.3.6 Disable Displaying Javascript in History URLs
// See:			http://kb.mozillazine.org/Browser.urlbar.filter.javascript
// Note:		Default true since FF 38.x
//user_pref("browser.urlbar.filter.javascript",		true);


// Disable HTML frames
// WARNING: might make your life difficult!
// NOTE: Removed since Firefox 38.0+
//user_pref("browser.frames.enabled",		false);


// Description: Enables click-to-play plugins
// See: 		https://wiki.mozilla.org/Firefox/Click_To_Play
// Also:		https://blog.mozilla.org/security/2012/10/11/click-to-play-plugins-blocklist-style/
// Note: 		Default set to true since FF 34.x
//user_pref("plugins.click_to_play",				true);


// Description: Enable automatically addons updates
// See:			https://blog.mozilla.org/addons/how-to-turn-off-add-on-updates/
// Note:		Enabled by default since FF 33.x
//user_pref("extensions.update.enabled",				true);


// Description:	Disables the internal collecting of telemetry data 
// See: 		https://wiki.mozilla.org/Platform/Features/Telemetry
// Also:		https://www.mozilla.org/en-US/legal/privacy/firefox.html#telemetry
// Also:		https://wiki.mozilla.org/Security/Reviews/Firefox6/ReviewNotes/telemetry
//user_pref("toolkit.telemetry.enabled",			false);


// Description: Disable FF  'hello' chat client
// See: 		https://wiki.mozilla.org/Loop
// Note: 		Can be enabled/disabled (default disabled) already within the normal settings
//user_pref("loop.enabled",					false);


// Description: CIS 2.1.1 Enable Auto Update, this is disabled for now. it is better to patch through package management
// See:			http://kb.mozillazine.org/App.update.auto
// Note:		Default true since FF 36.x
//user_pref("app.update.auto", true);


// Description: Disable SSDP
// See: 		https://bugzil.la/1111967
// Note:		Default set to false since FF 36.x
//user_pref("browser.casting.enabled",				false);


// Description: Disables the GMP for various codecs, in this example Oracles own H.264
// See: 		https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_media-capabilities
// Also:		http://andreasgal.com/2014/10/14/openh264-now-in-firefox/
//user_pref("media.gmp-gmpopenh264.enabled",			false);
// Note:		Some does not have such codec installed?! E.g. on Cyberfox/Pale Moon


// Description: Disallow NTLMv1
// See: 		https://bugzilla.mozilla.org/show_bug.cgi?id=828183
//user_pref("network.negotiate-auth.allow-insecure-ntlm-v1",	false);
// it is still allowed through HTTPS. uncomment the following to disable it completely.
//user_pref("network.negotiate-auth.allow-insecure-ntlm-v1-https",	false);
// Note: Doesn't exists anymore since FF 35.x


// Description: CSP ???
// See:			https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy
// Note:		Default true since Firefox 36.x
//user_pref("security.csp.enable",				true);


// Description: CIS Version 1.2.0 October 21st, 2011 2.2.3 Enable Warning of Using Weak Encryption
// See:			
//user_pref("security.warn_entering_weak",		true);



// Description: 
// See:			https://developer.mozilla.org/en/Preferences/Mozilla_preferences_for_uber-geeks
// Note:		CVE-2009-3555
//user_pref("security.ssl.warn_missing_rfc5746",		1);


// Description: 
// See:			https://bugzil.la/238789#c19
//user_pref("browser.helperApps.deleteTempFileOnExit",	true);


// Description: CIS Version 1.2.0 October 21st, 2011 2.5.5 Delete Download History
// Zero (0) is an indication that no download history is retained for the current profile.
//user_pref("browser.download.manager.retention",		0);


// Description: 
// See: 		http://kb.mozillazine.org/Browser.history_expire_visits
//user_pref("browser.history_expire_visits",		0);


// Description: 
// See: 		http://kb.mozillazine.org/Browser.history_expire_sites
//user_pref("browser.history_expire_sites",		0);



// Description: CIS Version 1.2.0 October 21st, 2011 2.5.4 Delete History and Form Data
// See:			http://kb.mozillazine.org/Browser.history_expire_days
//user_pref("browser.history_expire_days",		0);


// Description: Do not check if FF is the default browser
// See: 		
//user_pref("browser.shell.checkDefaultBrowser",		false);


// Description: 
// See: 		http://kb.mozillazine.org/Browser.sessionstore.postdata
// Note: 		Relates to CIS 2.5.7
//user_pref("browser.sessionstore.postdata",		0);
// See:			http://kb.mozillazine.org/Browser.sessionstore.enabled
//user_pref("browser.sessionstore.enabled",		false);


// Description: Disable collection of the data (the healthreport.sqlite* files)
// See: 		
//user_pref("datareporting.healthreport.service.enabled",	false);


// Description: 
// See:			https://wiki.mozilla.org/Tiles/Technical_Documentation#Ping
// Note: 		Doesn't exists anymore since latest 38.x 
//user_pref("browser.newtabpage.directory.ping",			"");


// Description: CIS Version 1.2.0 October 21st, 2011 2.1.3 Enable Information Bar for Outdated Plugins
// See:			
// Note: 		Doesn't exists anymore since latest 38.x 
//user_pref("plugins.hide_infobar_for_outdated_plugin",		false);


// Description: CIS Version 1.2.0 October 21st, 2011 2.5.3 Disable Prompting for Credential Storage
// See:			
// Note: 		Doesn't exists anymore since latest 38.x 
//user_pref("security.ask_for_password",		0);


// Description: Disable Pocket
// See:			http://techdows.com/2015/05/mozilla-integrates-pocket-into-firefox-nightly.html
// Note: 		Doesn't exist anymore since latest FF 38.x
//user_pref("browser.pocket.enabled",		false);


// Description: 
// See:			https://blog.mozilla.org/security/2012/11/01/preloading-hsts/
// Also:		https://wiki.mozilla.org/Privacy/Features/HSTS_Preload_List
// Note:		Default rtue since FF 38.x
//user_pref("network.stricttransportsecurity.preloadlist",	true);


// Description: Enable SPDY
// See:			https://en.wikipedia.org/wiki/SPDY
// Note: 		Default settings since FF 37.x
//user_pref("network.http.spdy.enabled",			true);
//user_pref("network.http.spdy.enabled.v3",		true);
//user_pref("network.http.spdy.enabled.v3-1",		true);


// Description: 
// See: 		https://www.blackhat.com/us-13/briefings.html#NextGen
// Note: 		Doesn't exists anymore since latest 38.x 
//user_pref("security.enable_tls_session_tickets",	false);


// Description: Configuration TLS  
// http://kb.mozillazine.org/Security.tls.version.max
// 1 = TLS 1.0 is the minimum required / maximum supported encryption protocol. (This is the current default for the maximum supported version)
// 2 = TLS 1.1 is the minimum required / maximum supported encryption protocol
// Note:		Default since latest FF 38.x
//user_pref("security.tls.version.min",			1);
//user_pref("security.tls.version.max",			3);


// Description: We could also disable security.ssl.errorReporting.enabled, but I think it's, good to leave the option to report potentially malicious sites if the user chooses to do so.
// See: 		https://support.mozilla.org/en-US/kb/certificate-pinning-reports
// Note:		Test available at: https://pinningtest.appspot.com/
// Note2: 		Default false since first FF 38.x 
//user_pref("security.ssl.errorReporting.automatic",		false);

