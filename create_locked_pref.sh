#!/bin/bash

cat > locked_user.js << EOF
/*******************************************************************************
// This file has been created by create_locked_pref.sh
//
// It's equivalent to the user.js with the only difference that the settings are
// locked and cannot be changed by the firefox user or firefox itself.
//
// NOTE: Use this in the system-wide configuration only and if you only want the
//       settings to locked.
//       See here: https://github.com/pyllyukko/user.js#system-wide-installation-all-platforms
//
/*******************************************************************************


EOF


sed 's/user_pref("/lockPref("/g' "user.js" >> locked_user.js

echo "Done!"
