rm -rf testromfs.zip
genromfs -f testromfs.img -d mk_fs_basedir -v -V "romfs"
zip -r testromfs.zip testromfs.img
#rm -rf testromfs.img
rm -rf /ftpfile/testromfs.zip
cp testromfs.zip /ftpfile

