#
#  Just a quick perl fgrep...
#
package fgrep;

sub main'fgrep {
    local($file, @exprs) = @_;
    local(@list);

    if (open file) {
	$code = "while (<file>) {\n\tchop;\n";
	for (@exprs) {
	    $code .= "\tpush(\@list, \$_), next if m\201${_}\201;\n";
	} 
	$code .= "}\n";
	warn "fgrep code is $code" if $debug;
	eval $code;
	warn "fgrep @exprs $file: $@\n" if $@;
    } elsif ($debug) {
	warn "main'fgrep: can't open $file: $!\n";
    } 

    @list;
} 

1;
