use ExtUtils::MakeMaker;

my $SSL_DIR = shift || "/usr/local/ssl";
die unless -f "$SSL_DIR/include/ssl.h";

WriteMakefile(
    NAME    => 'SSL',
    VERSION => '0.01',
    LIBS    => ["-L$SSL_DIR/lib -lssl -lcrypto"],
    INC     => "-I$SSL_DIR/include",
);
