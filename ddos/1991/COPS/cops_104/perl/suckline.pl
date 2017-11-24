#
#  As title implies... :-)
#
sub main'suckline {
    local($file, $_) = @_;
#   local($package) = caller;

#   $file =~ s/^([^']+)$/$package'$1/; 
    {
	if (s/\\\n?$//) {
	    $_ .= <$file>;
	    redo;
	}
    } 
    $_;
}

1;
