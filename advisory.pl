#!/usr/bin/perl

use strict;
use warnings;

use Try::Tiny;
use JSON;
use Data::Dumper;
use URI::Escape;

use LWP::UserAgent;
use LWP::Protocol::https;
use version;

sub main() {
	my ($filename) = @ARGV;
	my $product;
	my $vulnerable;
	my @cpeArray;
	my $issues;

	my $mport_cpe = `mport cpe`;

	my @text = split "\n", $mport_cpe;

	# example line from mport:     cpe:2.3:a:gnu:gmake:4.2.1:::::midnightbsd0:x64
	foreach my $cpe (@text) {
		@cpeArray = split /:/, $cpe;
		$issues = getIssues($cpeArray[3], $cpeArray[4]);

		foreach my $issue (@$issues) {
			$vulnerable = 0;
#			print Dumper($issue);
				foreach $product (@{$issue->{products}}) {
					if ($product->{name} eq $cpeArray[4]) {
						if (cmp_version($cpeArray[5], $product->{version}) eq 0) {
							$vulnerable = 1;
							last;
						}	
					}
				}

			if ($vulnerable eq 1) {	
				print "Vulnerable package $cpeArray[3] $cpeArray[4] $cpeArray[5]\n";
				print $issue->{cveId} . "\nDescription: " . $issue->{description} .  "\n";
				print "Severity: $issue->{severity}\n\n";
			}
		}
	}
}

sub getIssues() {
	my ($vendor, $product) = @_;
	my $server = 'sec.midnightbsd.org';

        my $REST= ({
            HOST  => "$server",
            URL   => "https://$server/api"
        });

	unless($vendor) {
		die "No vendor\n";
	}

	unless($product) {
		die "No product with vendor $vendor\n";
	}

        $REST->{UA} = LWP::UserAgent->new( keep_alive => 0 );

        $REST->{resource} = $REST->{URL} . ("/advisory/vendor/" .  uri_escape($vendor) . "/product/" .  uri_escape($product) ); #. "?startDate=2005-12-31");

        $REST->{request} = HTTP::Request->new( GET =>  $REST->{resource} );
        $REST->{response} = $REST->{UA}->request( $REST->{request} );

	try {
		return JSON->new->utf8->decode($REST ->{response}->content);
 	} catch {
#  		print "$_\n";
		print "Unable to check $vendor $product\n";
		return [];
	};
}

sub transform {
        my ($val) = @_;

	if ($val eq '~') {
		return -1;
	} elsif ($val =~ /^\d$/) {
		return $val * 1 + 1;
	} elsif ($val =~ /^[A-Za-z]$/) {
		return ord($val);
	} else {
		return ord($val) + 128;
	}
}

sub compare_string {
	my ($ver1, $ver2) = @_;
	
	my @a = map(transform($_), split(//, $ver1));
	my @b = map(transform($_), split(//, $ver2));
    
	while (1) {
		my ($a, $b) = (shift @a, shift @b);

		if (!defined($a) && !defined($b)) {
			return 0;
		}

		$a ||= 0;
		$b ||= 0;

		if ($a > $b) {
			return 1;
		} elsif ($a < $b) {
			return -1;
		}
	}
}


sub cmp_version {
	my ($ver1, $ver2) = @_;

	my @a = split_digits($ver1);
	my @b = split_digits($ver2);
    
	while (1) {
		my ($a, $b) = (shift @a, shift @b);
		my $cmp;

		if (!defined($a) && !defined($b)) {
			return 0;
		}

		$a ||= 0;
		$b ||= 0;

		# happy path.. numeric
		if ($a =~ /^\d+$/ and $b =~ /^\d+$/) {
			$cmp = $a <=> $b;
			if ($cmp) {
				return $cmp;
			}
		} else {
			$cmp = compare_string($a, $b);
			if ($cmp) {
				return $cmp;
		 	}
		}
	}
}

sub split_digits() {
	my ($num) = @_;

	return split(/(?<=\d)(?=\D)|(?<=\D)(?=\d)/, $num);
}

main();

1;
