#
#   This retrieves possibly cached owner of a file.
# If it returns "BOGUS", it means that the stat failed.

package main;
require 'stat.pl';

package file_owner;

sub main'Owner {
    local($file) = @_;

    if (!defined $owners{$file}) {
       if (&'Stat($file)) {
           $owners{$file} = $'st_uid;
       } else {
           $owners{$file} = 'BOGUS';
       }
    }
    $owners{$file};
}
