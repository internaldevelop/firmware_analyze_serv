rm -rf testSquashfs.zip
mkfs.jffs2 -r mk_fs_basedir -o testjffs2.jffs2
zip -r testjffs2.zip testjffs2.jffs2
#rm -rf testjffs2.jffs2
rm -rf /ftpfile/testjffs2.zip
cp testjffs2.zip /ftpfile

