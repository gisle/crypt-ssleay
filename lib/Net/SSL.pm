package Net::SSL;

use strict;
use vars qw(@ISA);

require IO::Socket;
@ISA=qw(IO::Socket::INET);

require Crypt::SSLeay;
