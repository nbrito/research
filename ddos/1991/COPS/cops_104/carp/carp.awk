BEGIN { LPP=40; line=0; }

/COPS/ {
  printf ("/title (%s) def\n",$0);
}

/hostname/ {
  #assume first three fields are "hostname     rep date"
  printf "/headray [ ";
  for (f=4; f <= NF; ++f) {
    printf ("(%s) ",$f);
  }
  print "] def";
  printf ("/numcols %d def\n",NF-3);
  print "dotitle";
  print "doheader";
  FS = "|"
}

/\|/ {
  ++line;
  #assumes spaces not tabs
  host=substr($1,0,index($1," ")-1);
  date=substr($1,index($1," "));
  #breaks in the year 2000
  date=substr(date,index(date,"1"));
  date=substr(date,0,index(date," ")-1);

  printf ("(%s) (%s) newline\n",host,date);
  for (f=2; f <= NF; ++f) {
    if ($f == 0) print "  dofull";
    else if ($f == 1) print "  dohalf";
    else if ($f == 2) print "  doempty";
    else print "  donothing";
  }
}

line != 0 && line%LPP == 0 {
  print "showpage";
  print "";
  print "dotitle";
  print "doheader";
}

END { print "showpage" }
