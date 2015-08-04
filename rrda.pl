#!/usr/bin/perl
# Copyright 2015 CentralNic Group plc. This program is Free Software; you can
# use it and/or modify it under the same terms as Perl itself.
package RRDA;
use bytes;
use Getopt::Long;
use HTTP::Server::Simple::CGI;
use JSON;
use Net::DNS;
use Pod::Usage;
use Sys::Syslog qw(:standard :macros);
use base qw(HTTP::Server::Simple::CGI);
use strict;

my $help;
my $debug;
my $host = '127.0.0.1';
my $port = 8080;
GetOptions(
	'host=s'	=> \$host,
	'port=i'	=> \$port,
	'help'		=> \$help,
	'debug'		=> \$debug,
);

pod2usage('-verbose' => 99, '-sections' => 'USAGE|OPTIONS') if ($help);

openlog(__PACKAGE__, 'ndelay,perror,pid', LOG_DAEMON);
setlogmask(LOG_UPTO($debug ? LOG_DEBUG : LOG_INFO));

my $server = RRDA->new;
$server->host($host);
$server->port($port);

if ($debug) {
	$server->run;

} else {
	$server->background;

}

sub err {
	return to_json({'code' => shift, 'message' => shift }, { 'pretty' => $debug });
}

sub valid_fqdn {
	my $domain = shift;
	return 1;
}

sub valid_server {
	my ($host, $port) = @_;
	return 1;
}

sub valid_qtype {
	my $type = shift;
	return 1;
}

sub handle_request {
	my ($self, $cgi) = @_;

	syslog(LOG_DEBUG, $cgi->path_info);

	my @parts = split(/\//, $cgi->path_info, 4);
	shift(@parts);
	my ($server, $domain, $type) = @parts;
	my ($host, $port) = split(/:/, $server, 2);

	($domain, $type) = ($type, 'PTR') if ('x' eq $domain);

	if (!valid_fqdn($domain)) {
		print $cgi->header('application/json', '400 Bad Request');
		print err(402, "Invalid domain name");

	} elsif (!valid_server($host, $port)) {
		print $cgi->header('application/json', '400 Bad Request');
		print err(403, "Invalid DNS server");

	} elsif (!valid_qtype($type)) {
		print $cgi->header('application/json', '400 Bad Request');
		print err(403, "Invalid query type");

	}

	if (!defined($self->{'resolver'})) {
		$self->{'resolver'} = Net::DNS::Resolver->new;
		$self->{'resolver'}->recurse(1);
		$self->{'resolver'}->persistent_udp(1);
		$self->{'resolver'}->persistent_tcp(1);
		$self->{'resolver'}->udp_timeout(3);
		$self->{'resolver'}->tcp_timeout(3);
		$self->{'resolver'}->retrans(1);
		$self->{'resolver'}->retry(3);
		$self->{'resolver'}->dnssec(1);
		$self->{'resolver'}->cdflag(1);
	}

	$self->{'resolver'}->nameservers($host);
	$self->{'resolver'}->port($port);

	my $res = $self->{'resolver'}->query($domain, $type);

	if (!$res) {
		print $cgi->header('application/json', '500 Internal Server Error');
		print err(501, "No response from $host on port $port");

	} elsif ('SERVFAIL' eq $res->header->rcode) {
		print $cgi->header('application/json', '500 Internal Server Error');
		print err(502, "SERVFAIL received from $host on port $port");

	} elsif ('NXDOMAIN' eq $res->header->rcode) {
		print $cgi->header('application/json', '500 Internal Server Error');
		print err(503, "NXDOMAIN received from $host on port $port");

	} elsif ('REFUSED' eq $res->header->rcode) {
		print $cgi->header('application/json', '500 Internal Server Error');
		print err(505, "REFUSED received from $host on port $port");

	} else {
		print $cgi->header('application/json', '200 OK');

		my $data = {
			'question' => {
				'name'	=> ($res->question)[0]->qname,
				'type'	=> ($res->question)[0]->qtype,
				'class'	=> ($res->question)[0]->qclass,
			},
		};

		my %sections = (
			'answer'	=> $res->header->ancount,
			'authority'	=> $res->header->nscount,
			'additional'	=> $res->header->arcount,
		);
		my %rrs = (
			'answer'	=> [ $res->answer ],
			'authority'	=> [ $res->authority ],
			'additional'	=> [ $res->additional ],
		);

		foreach my $section (keys(%sections)) {
			if ($sections{$section} > 0) {
				$data->{$section} = [];
				foreach my $rr (@{$rrs{$section}}) {
					next if ('OPT' eq $rr->type);
					push(@{$data->{$section}}, {
						'name' => $rr->name,
						'type' => $rr->type,
						'class' => $rr->class,
						'ttl' => $rr->ttl,
						'rdlength' => bytes::length($rr->rdata),
						'rdata' => $rr->rdstring,
					});
				}
			}
		}

		print to_json($data, { 'pretty' => $debug });
	}
}

1;