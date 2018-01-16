#!/bin/bash

cat > locked_user.js << EOF
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


EOF

sed 's/user_pref("/lockPref("/g' "user.js" >> locked_user.js \
    && echo "Successfully created locked_user.js."
