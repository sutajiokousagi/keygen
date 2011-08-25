#!/usr/bin/perl
# key generation and burning script --  bunnie@chumby.com

my $flag = $ARGV[0];

# check to see if we have previously been locked
system("regutil -w HW_OCOTP_CTRL_SET=0x3000"); # open the OTP banks for reading
system("regutil -w HW_OCOTP_CTRL_SET=0x3000");

$lockstateStr = `regutil -r HW_OCOTP_LOCK`;
@lockstateAry = split(/:/, $lockstateStr);
$lockstateHex = @lockstateAry[1];
$lockstateHex =~ s/^\s+//;
$lockstate = hex($lockstateHex);

if( $lockstate & 6291504 ) {
    print "Locked OTP detected, exiting and cleaning up OTP burning routines.\n";
    system("rm -f /tmp/keyfile");
    system("rm -f /tmp/keyfil.pub.bin.gpg"); 
    
    system("rm -f /psp/keygen");
    system("rm -f /psp/cp_eeprom");
    system("rm -f /psp/pubkey");
    system("rm -f /psp/keygen-script.pl");
    system("rm -f /psp/rfs1/userhook1");

    system("rm -f /psp/dcid");
    system("rm -f /psp/dcid.xml");

    system("rm -f /psp/hw_version");

    # just in case something weird happened
    system("regutil -w HW_RTC_PERSISTENT1_CLR=0x08000000");
    exit(0);
}

# if not locked, boldly go where no code has gone before. burn that sucka.
system("regutil -w HW_OCOTP_CTRL_CLR=0x3000");


# Kill the accelerometer.  We don't really need it during the key burning
# process.  Kill the control panel as well, as its watchdog would respawn
# the accelerometer.
system("stop_control_panel");
system("killall acceld");

# this sets the hardware version number.
# This will need to be changed to track the various models.  All Falconwing
# boards ought to be "xxxxxxxxA".
my $HWVERSION = "000000000000000000000000060A0000";
open(my $fh, '<', "/psp/hw_version");
if(defined($fh)) {
	my $version = <$fh>;
	close($fh);
	chomp $version;
	$version = int($version);
    if(int($version)==6) {
		$HWVERSION = "000000000000000000000000060A0000";
	}
	elsif(int($version)==7) {
		$HWVERSION = "000000000000000000000000070A0000";
	}
	elsif(int($version)==8) {
		$HWVERSION = "000000000000000000000000080A0000";
	}
	elsif(int($version)==9) {
		$HWVERSION = "000000000000000000000000090A0000";
	}
}


print "Using hardware version string $HWVERSION.\n";
print "Please make the code above matches the board's hardvare version number.\n";

# Grab the UID by unlocking the OTP, then reading it out of the Sigmatel-
# provided bank.
system("regutil -w HW_OCOTP_CTRL_SET=0x00001000");
my $uid_str = `regutil -r HW_OCOTP_OPS3`;
system("regutil -w HW_OCOTP_CTRL_CLR=0x00001000");

my @uid = split(/:/, $uid_str);
my $uidhex = ltrim($uid[1]);
print "Unique ID: $uidhex\n";

#my $channel = 8800; # start at low end of frequency range
#$channel = $channel + hex($uidhex) % 2000;

# set up entropy...noise (or even signal) from a random radio channel
#print `/bin/fmradio i`;
#print `/bin/fmradio t $channel`;
system("select_input line1");

# generate keys
my $uidint = hex($uidhex);
system("/psp/keygen $uidint $HWVERSION");

# encrypt "the package"
$ENV{'HOME'}="/tmp";
`date -s 202001010100`; # set date to jan 1 2020 because gpg is a bitch about time
`gpg --import /psp/pubkey`;
`gpg --yes --trust-model always -r duane\@chumby.com -e /tmp/keyfile.pub.bin`;
`rm -f /tmp/keyfile.pub.bin`;
`rm -f /tmp/keyfile.pub`;

# merge and write generated files to eeprom
system("/psp/cp_eeprom -w /tmp/keyfile /tmp/keyfile.pub.bin.gpg");
#verify that it's correct
my $restr = `/psp/cp_eeprom -w /tmp/keyfile /tmp/keyfile.pub.bin.gpg -k`;

if( $restr =~ m/EEPROM contents verify correct/ ) {
    print "EEPROM is just dandy.\n";
} else {
    print <<EOL;
\n
_____ _    ___ _     
|  ___/ \\  |_ _| |    
| |_ / _ \\  | |||    
|  _/ ___ \\ | || |___ 
|_|/_/   \\_\\___|_____|

EOL
    print "CPID programming fails integrity check.\n";
    while(1) {
        sleep(1000);
    }
}

if( $flag eq "t" ) {
    #don't nuke anything during testing
} else {
    # Program the DCID first.
    if(system("/psp/dcid -w /psp/dcid.xml")) {
        fail("Unable to write dcid");
    }

    # nuke keygen and everything else...
    system("rm -f /tmp/keyfile");
    system("rm -f /tmp/keyfil.pub.bin.gpg"); 

    system("rm -f /psp/keygen");
    system("rm -f /psp/cp_eeprom");
    system("rm -f /psp/pubkey");
    system("rm -f /psp/keygen-script.pl");
    system("rm -f /psp/rfs1/userhook1");

    system("rm -f /psp/dcid");
    system("rm -f /psp/dcid.xml");
}

# set the bit to say it's time to burn OTP
system("regutil -w HW_RTC_PERSISTENT1_SET=0x08000000");

if( $flag eq "t" ) {
    # don't reboot
} else {
    # reboot and burn AES keys into OTP
    system("reboot");
    while(1) {
        sleep(1000);
    }
}

# Left trim function to remove leading whitespace
sub ltrim($)
{
    my $string = shift;
    $string =~ s/^\s+//;
    return $string;
}

sub fail {
    die($@);
}
