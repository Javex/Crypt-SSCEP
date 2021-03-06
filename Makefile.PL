use 5.016002;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Crypt::SSCEP',
    VERSION_FROM      => 'lib/Crypt/SSCEP.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Crypt/SSCEP.pm', # retrieve abstract from module
       AUTHOR         => 'Gideon Knocke') : ()),
    LIBS              => ['-lcrypto'], # e.g., '-lm'
    DEFINE            => '-Wall', # e.g., '-DHAVE_SOMETHING'
    INC               => '-I.', # e.g., '-I. -I/usr/include/other'
	# Un-comment this if you add C files to link with later:
    OBJECT            => 'ias.o pkcs7.o helperfunctions.o SSCEP.o sceputils.o', # link all the C files too
);
