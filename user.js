/******************************************************************************
 * user.js                                                                    *
 * https://github.com/pyllyukko/user.js   
 * 
 * Additional Info for each category and preference can be found here:
 * https://github.com/pyllyukko/user.js/wiki
 ******************************************************************************/

/******************************************************************************
 * HTML5 / APIs / DOM                                                         *
 *                                                                            *
 ******************************************************************************/

user_pref("geo.enabled",		false);
user_pref("media.peerconnection.ice.default_address_only",		true);
user_pref("media.peerconnection.enabled",		false);
user_pref("media.navigator.enabled",		false);
user_pref("dom.battery.enabled",		false);
user_pref("dom.telephony.enabled",		false);
user_pref("beacon.enabled",		false);
user_pref("dom.event.clipboardevents.enabled",		false);
user_pref("dom.enable_performance",		false);
user_pref("media.webspeech.recognition.enable",		false);
user_pref("media.getusermedia.screensharing.enabled",		false);
user_pref("device.sensors.enabled",		false);
user_pref("browser.send_pings",		false);
user_pref("browser.send_pings.require_same_host",		true);

// TODO: find out why html5test still reports this as available
// NOTE: this is enabled for now, as disabling this seems to break some plugins.
//       see: http://forums.mozillazine.org/viewtopic.php?p=13842047#p13842047
//user_pref("dom.indexedDB.enabled",		true);

// TODO: "Access Your Location" "Maintain Offline Storage" "Show Notifications"



user_pref("dom.gamepad.enabled",		false);
user_pref("dom.vr.enabled",		false);
user_pref("dom.webnotifications.enabled",		false);
user_pref("webgl.disabled",		true);
//user_pref("pdfjs.enableWebGL",		false);

/******************************************************************************
 * Misc                                                                       *
 *                                                                            *
 ******************************************************************************/
 
user_pref("camera.control.face_detection.enabled",    false);
//user_pref("browser.search.defaultenginename",		"DuckDuckGo");
user_pref("clipboard.autocopy",		false);
user_pref("keyword.enabled",		false);
user_pref("browser.fixup.alternate.enabled",		false);
user_pref("network.proxy.socks_remote_dns",		true);
//user_pref("network.proxy.type", 0);
user_pref("security.mixed_content.block_active_content",		true);
user_pref("security.mixed_content.block_display_content",		true);
user_pref("javascript.options.methodjit.chrome",		false);
user_pref("javascript.options.methodjit.content",		false);
user_pref("network.jar.open-unsafe-types",		false);
user_pref("security.xpconnect.plugin.unrestricted",		false);
user_pref("security.fileuri.strict_origin_policy",		true);
user_pref("browser.urlbar.filter.javascript",		true);
//user_pref("browser.frames.enabled",		false);
user_pref("javascript.options.asmjs",		false);
user_pref("gfx.font_rendering.opentype_svg.enabled",		false);
user_pref("media.video_stats.enabled",		false);

/******************************************************************************
 * extensions / plugins                                                       *
 *                                                                            *
 ******************************************************************************/
 
//user_pref("xpinstall.signatures.required",   true);
user_pref("extensions.getAddons.cache.enabled",   false);
user_pref("plugin.state.flash",		0);
user_pref("plugin.state.libgnome-shell-browser-plugin",	0);
//user_pref("media.gmp-provider.enabled",		false);
user_pref("plugins.click_to_play",		true);
user_pref("extensions.update.enabled",		true);
user_pref("extensions.blocklist.enabled",		true);

/******************************************************************************
 * Firefox features / components                                              *
 *                                                                            *
 ******************************************************************************/

user_pref("toolkit.telemetry.enabled",		false);
user_pref("toolkit.telemetry.unified",		false);
user_pref("experiments.supported",		false);
user_pref("experiments.enabled",		false);
user_pref("privacy.trackingprotection.enabled",		true);
user_pref("privacy.trackingprotection.pbmode.enabled",		true);
user_pref("pdfjs.disabled",		true);
user_pref("datareporting.healthreport.uploadEnabled",		false);
user_pref("datareporting.healthreport.service.enabled",		false);
user_pref("datareporting.policy.dataSubmissionEnabled",		false);
user_pref("browser.newtabpage.enhanced",		false);
user_pref("browser.newtab.preload",		false);
user_pref("browser.newtabpage.directory.ping",		"");
user_pref("browser.newtabpage.directory.source",		"data:text/plain,{}");
user_pref("browser.selfsupport.url",		"");
//user_pref("loop.enabled",		false);
//user_pref("app.update.auto", true);
user_pref("browser.safebrowsing.enabled",		true);
user_pref("browser.safebrowsing.malware.enabled",		true);
user_pref("browser.safebrowsing.downloads.remote.enabled",	false);
user_pref("browser.pocket.enabled",		false);

/******************************************************************************
 * automatic connections                                                      *
 *                                                                            *
 ******************************************************************************/
 
user_pref("network.prefetch-next",		false);
user_pref("browser.search.geoip.url",		"");
user_pref("network.dns.disablePrefetch",		true);
user_pref("network.dns.disablePrefetchFromHTTPS",		true);
user_pref("network.predictor.enabled",		false);
user_pref("network.seer.enabled",		false);
user_pref("browser.search.suggest.enabled",		false);
user_pref("browser.urlbar.suggest.searches",		false);
user_pref("browser.casting.enabled",		false);
user_pref("media.gmp-gmpopenh264.enabled",		false);
user_pref("media.gmp-manager.url",		"");
user_pref("network.http.speculative-parallel-limit",		0);
user_pref("browser.aboutHomeSnippets.updateUrl",		"");
user_pref("browser.search.update",		false);

/******************************************************************************
 * HTTP                                                                       *
 *                                                                            *
 ******************************************************************************/
 
user_pref("network.negotiate-auth.allow-insecure-ntlm-v1",		false);
//user_pref("network.negotiate-auth.allow-insecure-ntlm-v1-https",		false);
user_pref("security.csp.experimentalEnabled",		true);
user_pref("security.csp.enable",		true);
user_pref("security.sri.enable",		true);
//user_pref("privacy.donottrackheader.enabled",		true);
//user_pref("network.http.sendRefererHeader",		1);
user_pref("network.http.referer.spoofSource",		true);
user_pref("network.http.sendSecureXSiteReferrer",		false);
user_pref("network.cookie.cookieBehavior",		1);
user_pref("network.cookie.thirdparty.sessionOnly",      true);
//user_pref("general.useragent.override", "Mozilla/5.0 (Windows NT 6.1; rv:31.0) Gecko/20100101 Firefox/31.0");

/******************************************************************************
 * Caching                                                                    *
 *                                                                            *
 ******************************************************************************/
 
user_pref("browser.sessionstore.postdata",		0);
user_pref("browser.sessionstore.enabled",		false);
user_pref("browser.cache.offline.enable",		false);
user_pref("browser.privatebrowsing.autostart",		true);
user_pref("extensions.ghostery.privateBrowsing",		true);
user_pref("privacy.sanitize.sanitizeOnShutdown",		true);
user_pref("privacy.clearOnShutdown.cache",		true);
user_pref("privacy.clearOnShutdown.cookies",		true);
user_pref("privacy.clearOnShutdown.downloads",		true);
user_pref("privacy.clearOnShutdown.formdata",		true);
user_pref("privacy.clearOnShutdown.history",		true);
user_pref("privacy.clearOnShutdown.offlineApps",		true);
user_pref("privacy.clearOnShutdown.passwords",		true);
user_pref("privacy.clearOnShutdown.sessions",		true);
//user_pref("privacy.clearOnShutdown.siteSettings",		false);
user_pref("places.history.enabled",		false);
user_pref("network.cookie.lifetimePolicy",		2);
user_pref("browser.cache.disk.enable",		false);
//user_pref("browser.cache.memory.enable",		false);
user_pref("browser.cache.disk_cache_ssl",		false);
user_pref("signon.rememberSignons",		false);
user_pref("browser.history_expire_days",		0);
user_pref("browser.history_expire_sites",		0);
user_pref("browser.history_expire_visits",		0);
user_pref("browser.download.manager.retention",		0);
user_pref("browser.formfill.enable",		false);
user_pref("browser.formfill.expire_days",		0);
user_pref("browser.sessionstore.privacy_level",		2);
user_pref("browser.helperApps.deleteTempFileOnExit",		true);
user_pref("browser.pagethumbnails.capturing_disabled",		true);

/******************************************************************************
 * UI related                                                                 *
 *                                                                            *
 ******************************************************************************/

//user_pref("dom.event.contextmenu.enabled",		false);
user_pref("browser.download.folderList",		2);
user_pref("browser.download.useDownloadDir",		false);
user_pref("browser.newtabpage.enabled",		false);
user_pref("browser.newtab.url",		"about:blank");
user_pref("plugins.update.notifyUser",		true);
user_pref("plugins.hide_infobar_for_outdated_plugin",		false);
user_pref("security.warn_entering_weak",		true);
user_pref("network.IDN_show_punycode",		true);
user_pref("browser.urlbar.autoFill",		false);
user_pref("browser.urlbar.autoFill.typed",		false);
user_pref("browser.urlbar.maxRichResults",		0);
user_pref("layout.css.visited_links_enabled",		false);
user_pref("browser.urlbar.autocomplete.enabled",		false);
user_pref("signon.autofillForms",		false);
user_pref("browser.shell.checkDefaultBrowser",		false);
user_pref("security.ssl.warn_missing_rfc5746",		1);
user_pref("security.ask_for_password",		0);

/******************************************************************************
 * TLS / HTTPS / OCSP related stuff                                           *
 *                                                                            *
 ******************************************************************************/
 
user_pref("network.stricttransportsecurity.preloadlist",		true);
user_pref("security.OCSP.enabled",		1);
user_pref("security.ssl.enable_ocsp_stapling",		true);
user_pref("security.OCSP.require",		true);
user_pref("security.enable_tls_session_tickets",		false);
user_pref("security.tls.version.min",		1);
user_pref("security.tls.version.max",		3);
user_pref("security.enable_ssl3",		false);
user_pref("security.cert_pinning.enforcement_level",		2);
user_pref("security.ssl.treat_unsafe_negotiation_as_broken",		true);
//user_pref("security.ssl.require_safe_negotiation",		true);
user_pref("security.ssl.errorReporting.automatic",		false);

/******************************************************************************
 * CIPHERS                                                                    *
 *                                                                            *
 * you can debug the SSL handshake with tshark: tshark -t ad -n -i wlan0 -T text -V -R ssl.handshake
 ******************************************************************************/
 
user_pref("security.ssl3.rsa_null_sha",		false);
user_pref("security.ssl3.rsa_null_md5",		false);
user_pref("security.ssl3.ecdhe_rsa_null_sha",		false);
user_pref("security.ssl3.ecdhe_ecdsa_null_sha",		false);
user_pref("security.ssl3.ecdh_rsa_null_sha",		false);
user_pref("security.ssl3.ecdh_ecdsa_null_sha",		false);
user_pref("security.ssl3.rsa_seed_sha",		false);
user_pref("security.ssl3.rsa_rc4_40_md5",		false);
user_pref("security.ssl3.rsa_rc2_40_md5",		false);
user_pref("security.ssl3.rsa_1024_rc4_56_sha",		false);
user_pref("security.ssl3.rsa_camellia_128_sha",		false);
user_pref("security.ssl3.ecdhe_rsa_aes_128_sha",		false);
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_sha",		false);
user_pref("security.ssl3.ecdh_rsa_aes_128_sha",		false);
user_pref("security.ssl3.ecdh_ecdsa_aes_128_sha",		false);
user_pref("security.ssl3.dhe_rsa_camellia_128_sha",		false);
user_pref("security.ssl3.dhe_rsa_aes_128_sha",		false);
user_pref("security.ssl3.ecdh_ecdsa_rc4_128_sha",		false);
user_pref("security.ssl3.ecdh_rsa_rc4_128_sha",		false);
user_pref("security.ssl3.ecdhe_ecdsa_rc4_128_sha",		false);
user_pref("security.ssl3.ecdhe_rsa_rc4_128_sha",		false);
user_pref("security.ssl3.rsa_rc4_128_md5",		false);
user_pref("security.ssl3.rsa_rc4_128_sha",		false);
user_pref("security.tls.unrestricted_rc4_fallback",		false);
user_pref("security.ssl3.dhe_dss_des_ede3_sha",		false);
user_pref("security.ssl3.dhe_rsa_des_ede3_sha",		false);
user_pref("security.ssl3.ecdh_ecdsa_des_ede3_sha",		false);
user_pref("security.ssl3.ecdh_rsa_des_ede3_sha",		false);
user_pref("security.ssl3.ecdhe_ecdsa_des_ede3_sha",		false);
user_pref("security.ssl3.ecdhe_rsa_des_ede3_sha",		false);
user_pref("security.ssl3.rsa_des_ede3_sha",		false);
user_pref("security.ssl3.rsa_fips_des_ede3_sha",		false);
user_pref("security.ssl3.ecdh_rsa_aes_256_sha",		false);
user_pref("security.ssl3.ecdh_ecdsa_aes_256_sha",		false);
user_pref("security.ssl3.rsa_camellia_256_sha",		false);
user_pref("security.ssl3.ecdhe_rsa_aes_256_sha",		true);
user_pref("security.ssl3.ecdhe_ecdsa_aes_256_sha",		true);
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256",		true);
user_pref("security.ssl3.ecdhe_rsa_aes_128_gcm_sha256",		true);
user_pref("security.ssl3.dhe_rsa_camellia_256_sha",		false);
user_pref("security.ssl3.dhe_rsa_aes_256_sha",		false);
user_pref("security.ssl3.dhe_dss_aes_128_sha",		false);
user_pref("security.ssl3.dhe_dss_aes_256_sha",		false);
user_pref("security.ssl3.dhe_dss_camellia_128_sha",		false);
user_pref("security.ssl3.dhe_dss_camellia_256_sha",		false);
user_pref("security.ssl3.rsa_aes_256_sha",		true);
user_pref("security.ssl3.rsa_aes_128_sha",		true);
