import argparse
from hermes_privilege_broker.build_packet import build_archive


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("release")
    parser.add_argument("output")
    args = parser.parse_args()
    build_archive(args.release, args.output)


if __name__ == "__main__":
    main()
