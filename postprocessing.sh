#!/bin/bash

# The script converts `user.js` into a sequence of commands for Firefox development 
# console, if you don't want to mess with a separate `user.js` file

grep '^user_pref' user.js |\
 cut -f2- -d"(" |\
 sed -e 's/);$//g' |\
 sed -e 's/^"/pref set /g' |\
 sed -e 's/^\(.\+\)",/\1 /g' > commands

# And then simply press Shift-F2, and paste the contents of commands
# with which you agree into the GCLI command line in your Firefox browser.
