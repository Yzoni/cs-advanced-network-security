import argparse


def merge_csvs(directory):
    pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('dir', type=str,
                        help='Directory with csv files')
    args = parser.parse_args()

    merge_csvs(args.dir)
