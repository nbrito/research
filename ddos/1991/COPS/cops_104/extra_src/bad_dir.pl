# this prints out "bad" directory names:

#   string of things that are OK; currently, this
# is anything that starts with a letter and number or the
# chars "#", "$", "-", or "+" (or the same situation, with a
# "." prepending):
$ok_string  = "\/\.?[A-Za-z0-9\#\$\-\+]+[^\/]*$";

# "." and ".." are cool, as are
# anything starting with the magic string;
# but any unprintables are bad...
if ((($ARGV[0] !~  /\.{1,2}$/) && ($ARGV[0] !~ /$ok_string/) &&
    ($ARGV[0] ne "/")) || ($ARGV[0] =~ /\.\..+$/) ||
    ($ARGV[0] =~ /[*\001-\040\177-\377]/)) {
		# print "MATCH: ###", $ARGV[0], "\@\@\@\n";
		print "\"", $ARGV[0], "\"\n";
		}
# else {
# 	print "\tNO MATCH: ###", $ARGV[0], "###\n";
# 	}

