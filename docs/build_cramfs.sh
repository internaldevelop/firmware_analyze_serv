rm -rf testcramfs.zip
mkcramfs mk_fs_basedir_mini testcramfs.cramfs
zip -r testcramfs.zip testcramfs.cramfs
rm -rf testcramfs.cramfs
rm -rf /ftpfile/testYaffs.zip
cp testcramfs.zip /ftpfile

