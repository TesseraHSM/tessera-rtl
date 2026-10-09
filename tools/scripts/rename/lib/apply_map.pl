#!/usr/bin/env perl
#
# apply_map.pl <map.tsv> <file> [<file> ...]
#
# Applies an identifier rename map to SystemVerilog/Verilog sources in a single
# pass per file.
#
# Map format (TAB separated):
#   <kind>\t<original>\t<renamed>
# where <kind> is one of: module | package | interface | macro | file
# Entries of kind "file" are ignored here (file names are handled by the
# caller), everything else is treated as a token rename.
#
# Why a single pass with one alternation instead of N sequential sed calls:
#   * Sequential passes can re-rename an already-renamed token
#     (e.g. `hmac` -> `tessera_hmac` -> `tessera_tessera_hmac`).
#   * Perl alternation is leftmost-FIRST (not leftmost-longest), so the
#     alternation is sorted by descending length to guarantee that
#     `hmac_reg_pkg` wins over `hmac`.
#
# Boundary handling: `\b` is NOT a correct SystemVerilog identifier boundary.
# SV identifiers may contain [A-Za-z0-9_$] and escaped identifiers start with a
# backslash. We therefore use explicit look-around character classes. A leading
# backtick (macro usage) is *not* in the class, so `` `HMAC_PARAM_PKG `` is
# matched and renamed correctly, and `tessera_hmac` is skipped because the
# character before `hmac` is `_`, which makes the rename idempotent.

use strict;
use warnings;

my $mapfile = shift @ARGV;
die "usage: apply_map.pl <map.tsv> <file>...\n" unless defined $mapfile && @ARGV;

my %map;
open(my $mh, '<', $mapfile) or die "apply_map.pl: cannot open $mapfile: $!\n";
while (my $line = <$mh>) {
    chomp $line;
    next if $line =~ /^\s*(#|$)/;
    my ($kind, $from, $to) = split(/\t/, $line);
    next unless defined $to && length $to;
    next if $kind eq 'file';
    if (exists $map{$from} && $map{$from} ne $to) {
        die "apply_map.pl: conflicting map entries for '$from'\n";
    }
    $map{$from} = $to;
}
close $mh;
die "apply_map.pl: map '$mapfile' contains no token entries\n" unless %map;

# Reverse-collision check: two originals must never collapse onto one new name.
my %seen_target;
for my $from (sort keys %map) {
    my $to = $map{$from};
    if (exists $seen_target{$to}) {
        die "apply_map.pl: collision - '$from' and '$seen_target{$to}' both map to '$to'\n";
    }
    $seen_target{$to} = $from;
}

my @keys = sort { length($b) <=> length($a) || $a cmp $b } keys %map;
my $alt  = join('|', map { quotemeta } @keys);
my $re   = qr/(?<![A-Za-z0-9_\$\\])($alt)(?![A-Za-z0-9_\$])/;

my $total = 0;
for my $file (@ARGV) {
    open(my $in, '<', $file) or die "apply_map.pl: cannot read $file: $!\n";
    local $/;
    my $text = <$in>;
    close $in;

    my $n = ($text =~ s/$re/$map{$1}/g) || 0;

    open(my $out, '>', $file) or die "apply_map.pl: cannot write $file: $!\n";
    print $out $text;
    close $out;

    printf STDERR "    %-46s %4d replacement(s)\n", $file, $n;
    $total += $n;
}
printf STDERR "    %-46s %4d total\n", '(all files)', $total;
