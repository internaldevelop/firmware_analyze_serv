rm -rf testSquashfs.zip
mksquashfs mk_fs_basedir testSquashfs.bin -noappend -all-root
zip -r testSquashfs.zip testSquashfs.bin
rm -rf test.squashfs testSquashfs.bin
rm -rf /ftpfile/testSquashfs.zip
cp testSquashfs.zip /ftpfile

