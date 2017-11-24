#
#  This retrieves a possibly cached mode on file.
# If it returns "BOGUS", it means that the stat failed.
#
# tchrist@convex.com

package main;
require 'stat.pl';

package file_mode;

sub main'Mode {
    local($file) = @_;

    if (!defined $modes{$file}) {
       if (&'Stat($file)) {
           $modes{$file} = $'st_mode;
       } else {
           $modes{$file} = 'BOGUS';
       }
    }
    $modes{$file};
}
