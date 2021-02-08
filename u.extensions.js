
/******************************************************************************
 * SECTION: Extensions / plugins                                                       *
 ******************************************************************************/

// PREF: Ensure you have a security delay when installing add-ons (milliseconds)
// http://kb.mozillazine.org/Disable_extension_install_delay_-_Firefox
// http://www.squarefree.com/2004/07/01/race-conditions-in-security-dialogs/
user_pref("security.dialog_enable_delay", 1000);

// PREF: Require signatures
// https://wiki.mozilla.org/Addons/Extension_Signing
//user_pref("xpinstall.signatures.required",		true);

// PREF: Opt-out of add-on metadata updates
// https://blog.mozilla.org/addons/how-to-opt-out-of-add-on-metadata-updates/
user_pref("extensions.getAddons.cache.enabled", false);

// PREF: Opt-out of themes (Persona) updates
// https://support.mozilla.org/t5/Firefox/how-do-I-prevent-autoamtic-updates-in-a-50-user-environment/td-p/144287
user_pref("lightweightThemes.update.enabled", false);

// PREF: Disable Flash Player NPAPI plugin
// http://kb.mozillazine.org/Flash_plugin
user_pref("plugin.state.flash", 0);

// PREF: Disable Java NPAPI plugin
user_pref("plugin.state.java", 0);

// PREF: Disable sending Flash Player crash reports
user_pref("dom.ipc.plugins.flash.subprocess.crashreporter.enabled", false);

// PREF: When Flash crash reports are enabled, don't send the visited URL in the crash report
user_pref("dom.ipc.plugins.reportCrashURL", false);

// PREF: When Flash is enabled, download and use Mozilla SWF URIs blocklist
// https://bugzilla.mozilla.org/show_bug.cgi?id=1237198
// https://github.com/mozilla-services/shavar-plugin-blocklist
user_pref("browser.safebrowsing.blockedURIs.enabled", true);

// PREF: Disable Shumway (Mozilla Flash renderer)
// https://developer.mozilla.org/en-US/docs/Mozilla/Projects/Shumway
user_pref("shumway.disabled", true);

// PREF: Disable Gnome Shell Integration NPAPI plugin
user_pref("plugin.state.libgnome-shell-browser-plugin", 0);

// PREF: Disable the bundled OpenH264 video codec (disabled)
// http://forums.mozillazine.org/viewtopic.php?p=13845077&sid=28af2622e8bd8497b9113851676846b1#p13845077
//user_pref("media.gmp-provider.enabled",		false);

// PREF: Enable plugins click-to-play
// https://wiki.mozilla.org/Firefox/Click_To_Play
// https://blog.mozilla.org/security/2012/10/11/click-to-play-plugins-blocklist-style/
user_pref("plugins.click_to_play", true);

// PREF: Updates addons automatically
// https://blog.mozilla.org/addons/how-to-turn-off-add-on-updates/
user_pref("extensions.update.enabled", true);

// PREF: Enable add-on and certificate blocklists (OneCRL) from Mozilla
// https://wiki.mozilla.org/Blocklisting
// https://blocked.cdn.mozilla.net/
// http://kb.mozillazine.org/Extensions.blocklist.enabled
// http://kb.mozillazine.org/Extensions.blocklist.url
// https://blog.mozilla.org/security/2015/03/03/revoking-intermediate-certificates-introducing-onecrl/
// Updated at interval defined in extensions.blocklist.interval (default: 86400)
user_pref("extensions.blocklist.enabled", true);
user_pref("services.blocklist.update_enabled", true);

// PREF: Decrease system information leakage to Mozilla blocklist update servers
// https://trac.torproject.org/projects/tor/ticket/16931
user_pref(
  "extensions.blocklist.url",
  "https://blocklist.addons.mozilla.org/blocklist/3/%APP_ID%/%APP_VERSION%/"
);
