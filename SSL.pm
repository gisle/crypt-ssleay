package SSL;

use strict;
use vars qw($VERSION @ISA);

require DynaLoader;

@ISA = qw(DynaLoader);
$VERSION = '0.01';

bootstrap SSL $VERSION;

package SSL::CTX;

sub DESTROY { shift->free; }

package SSL::Conn;

sub DESTROY { shift->free; }

package SSL;

1;
