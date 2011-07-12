use strict;
use DBI;

# This is very important ! Without this script will not get the filled hashesh from main.
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK $dbh $chkh $rplh $conn_valid %conf %redback_nas_ip_map %zte_nas_ip_map);
use Data::Dumper;

#
# This the remapping of return values
#
use constant    RLM_MODULE_REJECT=>    0;#  /* immediately reject the request */
use constant    RLM_MODULE_FAIL=>      1;#  /* module failed, don't reply */
use constant    RLM_MODULE_OK=>        2;#  /* the module is OK, continue */
use constant    RLM_MODULE_HANDLED=>   3;#  /* the module handled the request, so stop. */
use constant    RLM_MODULE_INVALID=>   4;#  /* the module considers the request invalid. */
use constant    RLM_MODULE_USERLOCK=>  5;#  /* reject the request (user is locked out) */
use constant    RLM_MODULE_NOTFOUND=>  6;#  /* user not found */
use constant    RLM_MODULE_NOOP=>      7;#  /* module succeeded without doing anything */
use constant    RLM_MODULE_UPDATED=>   8;#  /* OK (pairs modified) */
use constant    RLM_MODULE_NUMCODES=>  9;#  /* How many return codes there are */

#
# This the RADIUS log type
#  
use constant    RAD_LOG_DEBUG=>  0; 
use constant    RAD_LOG_AUTH=>   1; 
use constant    RAD_LOG_PROXY=>  2; 
use constant    RAD_LOG_INFO=>   3; 
use constant    RAD_LOG_ERROR=>  4; 


sub read_conf {
   $conf{'db_name'}="radius";
   $conf{'db_host'}="localhost";
   $conf{'db_user'}="radius";
   $conf{'db_passwd'}="radius_pwd";
    
   $zte_nas_ip_map{'10.255.254.5'}=1;
   $redback_nas_ip_map{'10.255.254.4'}=1;
   $redback_nas_ip_map{'10.255.254.6'}=1;
}

sub conn_db {
    $dbh->disconnect() if defined $dbh;
    # $dbh = DBI->connect("DBI:mysql:database=radius;host=localhost","radius","radius_pwd");
    $dbh = DBI->connect("DBI:mysql:database=$conf{'db_name'};host=$conf{'db_host'}",
                        $conf{'db_user'},
                        $conf{'db_passwd'});
    if ($DBI::err) {
        &radiusd::radlog(RAD_LOG_ERROR, "DB Connect Error. $DBI::errstr");
    } else {
        $chkh = $dbh->prepare("SELECT id,Value,nasip,deadline,now(),mac,vlan from radcheck where UserName=?");
        $rplh = $dbh->prepare("SELECT id,Attribute,Value from radreply where UserName=?");
    }
    $conn_valid = (! $DBI::err);
}

sub CLONE {
    &read_conf;
    &conn_db;
}

# Function to handle authorize
sub authorize {
    my $fall_log = RAD_LOG_DEBUG;
    my $success_log = RAD_LOG_DEBUG;
    my $update = ''; 

    delete $RAD_REPLY{'Reply-Message'};

    ##
    # Check DB Connect
    ##
    if( ! $conn_valid ) 
    {
        &conn_db; ## repair the Conncetion
        if (! $conn_valid ) {
            $RAD_REPLY{'Reply-Message'} = "Reject.Service Error";
            &radiusd::radlog($fall_log, "User $RAD_REQUEST{'User-Name'} reject.DB Connect Error.");
            return RLM_MODULE_REJECT;
        }
    }

    ##
    #   Proc Request MAC Vlan info
    # juniper 11/0.3 vlan-id 3
    # redback 5/3 vlan-id 159 
    # mac unified format xx-xx-xx-xx-xx-xx
    my $vlan = $RAD_REQUEST{'NAS-Port-Id'};
    my $mac ;
	# if( defined  $juniper_nas_ip_map{$RAD_REQUEST{'NAS-IP-Address'}}   ) {
	if( defined  $redback_nas_ip_map{$RAD_REQUEST{'NAS-IP-Address'}}   ) {
        ##	NAS-Port-Id = "5/3 vlan-id 159 pppoe 7464"
        ##  ==> 5/3 vlan-id 159
        $vlan =~ s/ pppoe \d+$// ;
        # Mac-Addr = "00-e0-4c-4a-02-6d"        
        $mac = $RAD_REQUEST{'Mac-Addr'};
    }
    elsif (defined  $zte_nas_ip_map{$RAD_REQUEST{'NAS-IP-Address'}}) {
        #ZTE
        #Calling-Station-Id = "010600000009d900e0b122857d"
        $mac='';
        for(my $i=0;$i<12;$i=$i+2){
            $mac = $mac.substr($RAD_REQUEST{'Calling-Station-Id'},14+$i,2)."-"
        }
        $mac=substr($mac,0,17);        
    }
    else{
        ####################################
        ##NAS-Port-Id = "gigabitEthernet 11/0.3:3"
        ##               GigabitEthernet 12/0/1.3:3
        ## ==>  11/0.3 vlan 3
        if ($vlan =~ /^([gG]igabit|[fF]ast)Ethernet [\d.:\/]+$/ ){
            $vlan =~ s/^([gG]igabit|[fF]ast)Ethernet *//;
            $vlan =~ s/^(.*)(:)(\d+)$/$1 vlan $3/ ;
        }
        else
        {
            $vlan='';
        }
        ##ERX-Pppoe-Description = "pppoe 12:34:56:78:9a:bc"
        ##  ==> 12-34-56-78-9a-bc
        $mac = $RAD_REQUEST{'ERX-Pppoe-Description'};
        $mac =~ s/pppoe //;
        $mac =~ s/:/-/g;
    }

    ## Check UserName and Password
    ## UserName and Password is all digit
    if (! ($RAD_REQUEST{'User-Name'} =~ /^\d+$/ && 
           $RAD_REQUEST{'User-Password'} =~ /^\d+$/ ) ){
        $RAD_REPLY{'Reply-Message'} = "Reject.UserName or Password no digit";
        &radiusd::radlog($fall_log, "User $RAD_REQUEST{'User-Name'} digit error.[mac=$mac,vlan=$vlan,nasip=$RAD_REQUEST{'NAS-IP-Address'}]");
        return RLM_MODULE_REJECT;
    }


    $chkh->execute($RAD_REQUEST{'User-Name'});
    if (DBI::err){
        &radiusd::radlog($fall_log, "DB TimeOut.reconnect");
        &conn_db; ## repair connetion for timeout conn
        if ($conn_valid ) {
            $chkh->execute($RAD_REQUEST{'User-Name'});
            if (DBI::err){
                $RAD_REPLY{'Reply-Message'} = "Reject.Service Error";
                &radiusd::radlog($fall_log, "User $RAD_REQUEST{'User-Name'} reject.DB Query Error.");
                return RLM_MODULE_REJECT;
            }
        } else {
            $RAD_REPLY{'Reply-Message'} = "Reject.Service Error";
            &radiusd::radlog($fall_log, "User $RAD_REQUEST{'User-Name'} reject.DB Connect Error.");
            return RLM_MODULE_REJECT;
        }
    }


    my @value = $chkh->fetchrow_array();
    if (! exists $value[0]) {
        # user not exsit
        $RAD_REPLY{'Reply-Message'} = "Reject.UserName Not Exist";
        &radiusd::radlog($fall_log, "User $RAD_REQUEST{'User-Name'} not exist.[mac=$mac,vlan=$vlan,nasip=$RAD_REQUEST{'NAS-IP-Address'}]");
        return RLM_MODULE_REJECT;
    }
    ### SQL Query Result    
    ###0   1     2      3      4     5   6
    ##id,Value,nasip,deadline,now(),mac,vlan
    if($value[1] ne $RAD_REQUEST{"User-Password"} ) {
        $RAD_REPLY{'Reply-Message'} = "Reject.Password Error";
        &radiusd::radlog($fall_log, "User $RAD_REQUEST{'User-Name'} password error.[mac=$mac,vlan=$vlan,nasip=$RAD_REQUEST{'NAS-IP-Address'}].$value[1] ne $RAD_REQUEST{'User-Password'}");
        return RLM_MODULE_REJECT;
    }
    ###Check Deadline
    if($value[3] lt  $value[4]){
        $RAD_REPLY{'Reply-Message'} = "Reject. User Out of Date";
        &radiusd::radlog($fall_log, "User $RAD_REQUEST{'User-Name'} account expired.[mac=$mac,vlan=$vlan,nasip=$RAD_REQUEST{'NAS-IP-Address'}]");
        return RLM_MODULE_REJECT;
    }



    ## Check Mac Address
    if( (!defined $value[5]) || $value[5] eq "" ){
        $update = $update."mac='$mac',"; 
    } elsif ($value[5] ne $mac) {
        $RAD_REPLY{'Reply-Message'} = "Reject,Mac Address Error";
        &radiusd::radlog($fall_log, 
                         "User $RAD_REQUEST{'User-Name'} Mac Address error.[mac=$mac,vlan=$vlan,nasip=$RAD_REQUEST{'NAS-IP-Address'}]");
        return RLM_MODULE_REJECT;
    }
    
    ## Check nas ip
    if( (!defined $value[2]) || $value[2] eq "" ){
        $update = $update."nasip='".$RAD_REQUEST{'NAS-IP-Address'}."'," 
    } 
    elsif($value[2] ne $RAD_REQUEST{"NAS-IP-Address"} ) {
        $RAD_REPLY{'Reply-Message'} = "Reject,NAS-IP Error";
        &radiusd::radlog($fall_log, 
                         "User $RAD_REQUEST{'User-Name'} NAS-IP $value[2] ne $RAD_REQUEST{'NAS-IP-Address'} error.[mac=$mac,vlan=$vlan,nasip=$RAD_REQUEST{'NAS-IP-Address'}]");
        return RLM_MODULE_REJECT;
    }

    my %attr_map;
    my @row;
    ## Exec SQL,Dump all Attribs to attr_map
    $rplh->execute($RAD_REQUEST{'User-Name'});
    if (DBI::err){
        &radiusd::radlog($fall_log, "User $RAD_REQUEST{'User-Name'} accept.DB Query Attr Error.");
    } else {

        $attr_map{$row[1]} = $row[2]  while(@row = $rplh->fetchrow_array);
        ## Replay Vendor's Attributes
        if( defined  $redback_nas_ip_map{$RAD_REQUEST{'NAS-IP-Address'}}   ) {
            #redback
            $RAD_REPLY{'Qos-Policy-Metering'} = $attr_map{'Qos-Policy-Metering'} ;
            $RAD_REPLY{'Qos-Policy-Policing'} = $attr_map{'Qos-Policy-Policing'} ;
        } 
        elsif (defined  $zte_nas_ip_map{$RAD_REQUEST{'NAS-IP-Address'}} ){
            #FOR DEBUG
#            my @zte_key = keys(%RAD_REQUEST);
#            foreach (@zte_key){
#                &radiusd::radlog($fall_log, "ZTE DEBUG: $_ ==> $RAD_REQUEST{$_}.");
#            }

#            $RAD_REPLY{'ZTE-Rate-Ctrl-Scr-Down'}=2048;
#            $RAD_REPLY{'ZTE-Rate-Ctrl-Scr-Up'}= 2048;

            #&radiusd::radlog($fall_log, "ZTE DEBUG: $attr_map{'Qos-Policy-Metering'} $attr_map{'Qos-Policy-Policing'}.");
            $RAD_REPLY{'ZTE-Qos-Profile-Down'}=$attr_map{'Qos-Policy-Metering'} ;
            $RAD_REPLY{'ZTE-Qos-Profile-Up'}=$attr_map{'Qos-Policy-Policing'} ;

        } 
        else {
            #Juniper
            $RAD_REPLY{'ERX-Egress-Policy-Name'}=$attr_map{'Qos-Policy-Metering'} ;
            $RAD_REPLY{'ERX-Ingress-Policy-Name'}=$attr_map{'Qos-Policy-Policing'} ;
            $RAD_REPLY{'ERX-Service-Bundle'}="Portal:$attr_map{'Qos-Policy-Policing'}-$attr_map{'Qos-Policy-Metering'}";
            # session Timeout = 345600 (96hour) 
            # Session-Timeout
            $RAD_REPLY{'Session-Timeout'}= "345600";
        } 

        delete($attr_map{'Qos-Policy-Metering'});
        delete($attr_map{'Qos-Policy-Policing'});
        # delete($attr_map{'ERX-Max-Clients-Per-Interface'});

 
        ### Replay Standard Attributes.
        ### DEFINE : The remaining is Standard Attributes.
        ### Write the remaining attrs into replay
        my ($attr_name,$attr_value);
        $RAD_REPLY{$attr_name} = $attr_value  while ( ($attr_name,$attr_value) = each %attr_map );
    }

#     ## !!ONLY FOR TEST!!
#     while ( ($attr_name,$attr_value) = each %RAD_REPLY ){
#         &radiusd::radlog($success_log, "TEST RAD_REPLY :$attr_name => $attr_value") ;
#     }

    ## Write VLan to DB  
    ## $value[6]=>vlan
    ## 1 Check $vlan
    ## 2 Check DB Field: 1)NULL 2) "" 3) not equal  

    if( ( $vlan ne '' ) && 
        ((!defined $value[6]) || $value[6] eq "" || $value[6] ne $vlan )  ) {
        $update = $update."vlan='$vlan',"; 
    }
    
    if($update ne '' ) {
        $update =~ s/,$// ;
        my $sql = "update radcheck set $update where UserName='".$RAD_REQUEST{'User-Name'}."' ";
        $dbh->do($sql);
        if (DBI::err){
            &radiusd::radlog($fall_log, "DB Update Error.SQL:$sql");
        } else {
            &radiusd::radlog($success_log, "SQL:$sql");
        }
    }
    &radiusd::radlog($success_log, "User $RAD_REQUEST{'User-Name'} Accept.[mac=$mac,vlan=$vlan,nasip=$RAD_REQUEST{'NAS-IP-Address'}]");
    return RLM_MODULE_OK;
}

# Function to handle authenticate
sub authenticate {
        # Accept user and set some attribute
        return RLM_MODULE_OK;
}

# Function to handle preacct
sub preacct {
        # For debugging purposes only
#       &log_request_attributes;

        return RLM_MODULE_OK;
}

# Function to handle accounting
sub accounting {
        # For debugging purposes only
#       &log_request_attributes;
        # You can call another subroutine from here
        # &test_call;

        return RLM_MODULE_OK;
}

# Function to handle checksimul
sub checksimul {
        # For debugging purposes only
#       &log_request_attributes;

        return RLM_MODULE_OK;
}

# Function to handle pre_proxy
sub pre_proxy {
        # For debugging purposes only
#       &log_request_attributes;

        return RLM_MODULE_OK;
}

# Function to handle post_proxy
sub post_proxy {
        # For debugging purposes only
#       &log_request_attributes;

        return RLM_MODULE_OK;
}

# Function to handle post_auth
sub post_auth {
        # For debugging purposes only

        $RAD_REPLY{'Reply-Message'} = "Hi, I Changed It.";
        return RLM_MODULE_OK;
}

# Function to handle xlat
sub xlat {
        # For debugging purposes only
#       &log_request_attributes;

        # Loads some external perl and evaluate it
        my ($filename,$a,$b,$c,$d) = @_;
        &radiusd::radlog(1, "From xlat $filename ");
        &radiusd::radlog(1,"From xlat $a $b $c $d ");
        local *FH;
        open FH, $filename or die "open '$filename' $!";
        local($/) = undef;
        my $sub = <FH>;
        close FH;
        my $eval = qq{ sub handler{ $sub;} };
        eval $eval;
        eval {main->handler;};
}

# Function to handle detach
sub detach {
        # For debugging purposes only
#       &log_request_attributes;

        # Do some logging.
        &radiusd::radlog(0,"rlm_perl::Detaching. Reloading. Done.");
}
