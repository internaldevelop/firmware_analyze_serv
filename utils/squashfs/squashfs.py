from PySquashfsImage import SquashFsImage
import os

class MySquashfs:
    # https://github.com/matteomattei/PySquashfsImage



    @staticmethod
    def squash_fs_file(sq_file, path, sub_path):
        list = []
        newpath = MySquashfs.create_path(path + sub_path)

        image = SquashFsImage(sq_file)

        for i in image.root.findAll():
            if i.isFolder():
                print(i.getPath())
                localpath = MySquashfs.create_path(newpath + i.getPath())

            if i.getName() != '':
                print(i.getPath())
                print(i.getName())
                with open(localpath.encode() + b'/' + i.getName(), 'wb') as f:
                    # print(b'Saving original ' + path.encode() + i.getPath().encode() + i.getName())
                    f.write(i.getContent())

                list.append({
                    'name': i.getPath().encode(),
                    'length': i.getLength(),
                    'mode': i.inode.mode,
                    'time': i.inode.time
                })
        image.close()

        return list

    @staticmethod
    def create_path(local_path):
        if os.path.isdir(local_path):
            pass
        else:
            os.mkdir(local_path)
        return local_path