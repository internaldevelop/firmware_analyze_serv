rm -rf testYaffs.zip
mkyaffsimage mk_fs_basedir testYaffs.img
zip -r testYaffs.zip testYaffs.img
#rm -rf testYaffs.img
rm -rf /ftpfile/testYaffs.zip
cp testYaffs.zip /ftpfile

