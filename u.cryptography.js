/******************************************************************************
 * SECTION: Cryptography                                                      *
 ******************************************************************************/

// PREF: Enable HSTS preload list (pre-set HSTS sites list provided by Mozilla)
// https://blog.mozilla.org/security/2012/11/01/preloading-hsts/
// https://wiki.mozilla.org/Privacy/Features/HSTS_Preload_List
// https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
user_pref("network.stricttransportsecurity.preloadlist", true);

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
user_pref("security.OCSP.enabled", 1);

// PREF: Enable OCSP Stapling support
// https://en.wikipedia.org/wiki/OCSP_stapling
// https://blog.mozilla.org/security/2013/07/29/ocsp-stapling-in-firefox/
// https://www.digitalocean.com/community/tutorials/how-to-configure-ocsp-stapling-on-apache-and-nginx
user_pref("security.ssl.enable_ocsp_stapling", true);

// PREF: Enable OCSP Must-Staple support (Firefox >= 45)
// https://blog.mozilla.org/security/2015/11/23/improving-revocation-ocsp-must-staple-and-short-lived-certificates/
// https://www.entrust.com/ocsp-must-staple/
// https://github.com/schomery/privacy-settings/issues/40
// NOTICE: Firefox falls back on plain OCSP when must-staple is not configured on the host certificate
user_pref("security.ssl.enable_ocsp_must_staple", true);

// PREF: Require a valid OCSP response for OCSP enabled certificates
// https://groups.google.com/forum/#!topic/mozilla.dev.security/n1G-N2-HTVA
// Disabling this will make OCSP bypassable by MitM attacks suppressing OCSP responses
// NOTICE: `security.OCSP.require` will make the connection fail when the OCSP responder is unavailable
// NOTICE: `security.OCSP.require` is known to break browsing on some [captive portals](https://en.wikipedia.org/wiki/Captive_portal)
user_pref("security.OCSP.require", true);

// PREF: Disable TLS Session Tickets
// https://www.blackhat.com/us-13/briefings.html#NextGen
// https://media.blackhat.com/us-13/US-13-Daigniere-TLS-Secrets-Slides.pdf
// https://media.blackhat.com/us-13/US-13-Daigniere-TLS-Secrets-WP.pdf
// https://bugzilla.mozilla.org/show_bug.cgi?id=917049
// https://bugzilla.mozilla.org/show_bug.cgi?id=967977
user_pref("security.ssl.disable_session_identifiers", true);

// PREF: Only allow TLS 1.[0-3]
// http://kb.mozillazine.org/Security.tls.version.*
// 1 = TLS 1.0 is the minimum required / maximum supported encryption protocol. (This is the current default for the maximum supported version.)
// 2 = TLS 1.1 is the minimum required / maximum supported encryption protocol.
user_pref("security.tls.version.min", 1);
user_pref("security.tls.version.max", 4);

// PREF: Disable insecure TLS version fallback
// https://bugzilla.mozilla.org/show_bug.cgi?id=1084025
// https://github.com/pyllyukko/user.js/pull/206#issuecomment-280229645
user_pref("security.tls.version.fallback-limit", 3);

// PREF: Enfore Public Key Pinning
// https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning
// https://wiki.mozilla.org/SecurityEngineering/Public_Key_Pinning
// "2. Strict. Pinning is always enforced."
user_pref("security.cert_pinning.enforcement_level", 2);

// PREF: Disallow SHA-1
// https://bugzilla.mozilla.org/show_bug.cgi?id=1302140
// https://shattered.io/
user_pref("security.pki.sha1_enforcement_level", 1);

// PREF: Warn the user when server doesn't support RFC 5746 ("safe" renegotiation)
// https://wiki.mozilla.org/Security:Renegotiation#security.ssl.treat_unsafe_negotiation_as_broken
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-3555
user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);

// PREF: Disallow connection to servers not supporting safe renegotiation (disabled)
// https://wiki.mozilla.org/Security:Renegotiation#security.ssl.require_safe_negotiation
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-3555
// TODO: `security.ssl.require_safe_negotiation` is more secure but makes browsing next to impossible (2012-2014-... - `ssl_error_unsafe_negotiation` errors), so is left disabled
//user_pref("security.ssl.require_safe_negotiation",		true);

// PREF: Disable automatic reporting of TLS connection errors
// https://support.mozilla.org/en-US/kb/certificate-pinning-reports
// we could also disable security.ssl.errorReporting.enabled, but I think it's
// good to leave the option to report potentially malicious sites if the user
// chooses to do so.
// you can test this at https://pinningtest.appspot.com/
user_pref("security.ssl.errorReporting.automatic", false);

// PREF: Pre-populate the current URL but do not pre-fetch the certificate in the "Add Security Exception" dialog
// http://kb.mozillazine.org/Browser.ssl_override_behavior
// https://github.com/pyllyukko/user.js/issues/210
user_pref("browser.ssl_override_behavior", 1);
