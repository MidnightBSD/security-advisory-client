#!/usr/bin/perl

use strict;
use warnings;

use JSON;
use Data::Dumper;

use LWP::UserAgent;
use Scalar::Util qw(looks_like_number);
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
						if (cmp_version($cpeArray[5], $product->{version})) {
							$vulnerable = 1;
							last;
						}	
					}
				}

			if ($vulnerable eq 1) {	
				print "Vulnerable package $cpeArray[3] $cpeArray[4] $cpeArray[5]\n";
				print $issue->{cveId} . "\nDescription: " . $issue->{description} .  "\n";
				print "Severity $issue->{severity}";
				print "\n";
			}
		}
	}
}

sub getIssues() {
	my ($vendor, $product) = @_;
	my $server = 'sec.midnightbsd.org';

        my $REST= ({
            HOST  => "$server",
            URL   => "http://$server/api"
        });

	unless($vendor) {
		die "No vendor\n";
	}

	unless($product) {
		die "No product with vendor $vendor\n";
	}

        $REST->{UA} = LWP::UserAgent->new( keep_alive => 0 );

        $REST->{resource} = $REST->{URL} . ("/advisory/vendor/" . $vendor . "/product/" . $product );

        $REST->{request} = HTTP::Request->new( GET =>  $REST->{resource} );
        $REST->{response} = $REST->{UA}->request( $REST->{request} );

	return JSON->new->utf8->decode($REST ->{response}->content);
}

sub cmp_version() {
	my ($a, $b) = @_;

	if (looks_like_number($a) && looks_like_number($b)) {
		return $b >= $a;
	}

	return version->declare($b)->numify >= version->declare($a)->numify;

#	my $a1 = $a =~ s/\.//gi;
#	my $b1 = $b =~ s/\.//gi;

#	return $b1 >= $a1;
}


main();

1;
