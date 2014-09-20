#!/usr/bin/perl
# Perl eval plugin for DaZeus
# Copyright (C) 2007  Sjors Gielen
# Copyright (C) 2014  Aaron van Geffen
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

use DaZeus;
use strict;
use warnings;

use Data::Dumper;
use Math::Complex; # tan, atan, etc.
use PerlIO;
use PerlIO::scalar;
use Scalar::Util;
use List::Util;
use Tie::Hash;
use Tie::Scalar;
use Tie::Array;
use BSD::Resource;
use Symbol qw/delete_package/;
use POSIX;
use Carp::Heavy;
use IPC::Run;
use Try::Tiny;

my ($socket) = @ARGV;
if(!$socket) {
	die "Usage: $0 socket\n";
}

my $dazeus = DaZeus->connect($socket) or die $!;

# Based very heavily on Buubot's (?:\w+)eval.pm; buu wrote most of this code.
$dazeus->subscribe_command("eval" => \&run_eval);
while($dazeus->handleEvents()) {}

sub run_eval {
	my ($self, $network, $sender, $channel, $command, $code) = @_;

	warn("EVAL by $sender in $channel: $code\n");
	my $output = "";

	my $h;
	my $outer_pid = $$;
	try {
		$h = IPC::Run::harness(sub {
			try {
				safe_execute("perl", $code, $channel, $sender);
			} catch {
				die;
#line 1 eval
			};
			exit(0);
		}, '>', \$output, '2>', \$output, IPC::Run::timeout(10));
		$h->start();
		$h->finish();
	} catch {
		$output .= $_;
	};

	$h->kill_kill if $h;

	$output =~ s/\r?\n/ /g;
	$output =~ s/[^\x20-\x7f]/ /g;

	reply($output, $network, $sender, $channel);
}

sub reply {
	my ($response, $network, $sender, $channel) = @_;

	if ($channel eq $dazeus->getNick($network)) {
		$dazeus->message($network, $sender, $response);
	} else {
		$dazeus->message($network, $channel, $response);
	}
}

sub safe_execute {
	my ($language, $code, $channel, $target) = @_;

	if($< == 0) {
		die "Refusing to run as root.\n";
	}

	$|++;

	if($channel ne 'msg' and defined $target and $target ne "") {
		print "$target:\n";
	}

	$<=$>=65534;
	POSIX::setgid(65534);
	
	setrlimit(RLIMIT_CPU, 10, 10);
	setrlimit(RLIMIT_DATA, 32*1024, 32*1024);
	setrlimit(RLIMIT_STACK, 32*1024, 32*1024);
	setrlimit(RLIMIT_NPROC, 1, 1);
	setrlimit(RLIMIT_NOFILE, 0, 0);
	setrlimit(RLIMIT_OFILE, 0, 0);
	setrlimit(RLIMIT_OPEN_MAX, 0, 0);
	setrlimit(RLIMIT_LOCKS, 0, 0);
	setrlimit(RLIMIT_AS, 32*1024, 32*1024);
	setrlimit(RLIMIT_VMEM, 32*1024, 32*1024);
	setrlimit(RLIMIT_MEMLOCK, 100, 100);
	die "Failed to drop root: $<" if $< == 0;
	close STDIN;
	local $@;
	for( qw/Socket IO::Socket::INET/ ) {
		delete_package( $_ );
	}
	local @INC;

	{
		if($language eq "perl") {
			evaler($code);
		} else {
			print "Unknown language.";
		}
	}
}

sub pretty {
	my $ch = shift;
	return '\n' if $ch eq "\n";
	return '\t' if $ch eq "\t";
	return '\0' if ord $ch == 0;
	return sprintf '\x%02x', ord $ch if ord $ch < 256;
	return sprintf '\x{%x}', ord $ch;
}

sub evaler {
	# THIS SUB MUST ALWAYS BE RUN IN A DIFFERENT PROCESS!
	my $code = shift;
	$| = 1;
	$! = undef;
	local %ENV=();
	srand;
	my @OS = ('Microsoft Windows', 'Linux', 'NetBSD', 'FreeBSD', 'Solaris', 'OS/2 Warp', 'OSX');
	local $^O = $OS[rand@OS];
	
	my $deny_code = "";
	# Disallow calls that may change the filesystem, shared memory
	# or other processes, or that give away sensitive information.
	for( "msgctl", "msgget", "msgrcv", "msgsnd", "semctl", "semget",
		"semop", "shmctl", "shmget", "shmread", "shmwrite", "unlink",
		"chmod", "chown", "opendir", "link", "mkdir", "stat",
		"rename", "rmdir", "stat", "syscall", "truncate" )
	{
		$deny_code .= "*CORE::GLOBAL::$_ = sub {die}; \n";
	}
	
	my $ret;
	{
		local $\=" ";
		$ret = eval (
			"no strict; no warnings; package main;
			BEGIN{ $deny_code }\n#line 1 eval
			$code"
		);
	}
	no warnings;
	$ret =~ s/\s+$//;
	if( $@ ) {
		print "Error: $@\n";
	} else {
		print " ";
		if( ref $ret ) {
			local $Data::Dumper::Terse = 1;
			local $Data::Dumper::Quotekeys = 0;
			local $Data::Dumper::Indent = 0;
			$ret = Dumper( $ret );
			print $ret;
		} elsif($ret =~ /[^\x20-\x7e]/) {
			$ret =~ s/\\/\\\\/g;
			$ret =~ s/"/\"/g;
			$ret =~ s/([^\x20-\x73])/pretty($1)/eg;
			print qq{$ret};
		} else {
			print $ret;
		}
		print "\n";
	}
}

1;
