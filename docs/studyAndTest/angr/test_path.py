import os
import angr

root_path = os.path.dirname(os.path.realpath(__file__))
samples_path = os.path.join(root_path, 'samples')


def path_analyze(proj):
    pgourp = proj.factory.path_group()

    while len(pgourp.active) > 0:
        pgourp.step()
        print(pgourp)
    return


def test_path():
    proj = angr.Project(os.path.join(samples_path, '../../../files/samples/ais3_crackme'), load_options={'auto_load_libs': False})

    path_analyze(proj)


if __name__ == "__main__":
    test_path()
