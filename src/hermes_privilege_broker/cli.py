import argparse
import json

from .packaging import Installer

def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", nargs="?", default="plan", choices=("plan", "apply", "update", "verify", "uninstall"))
    args = parser.parse_args(argv)
    installer = Installer()
    if args.action == "plan":
        print(json.dumps(installer.plan(), indent=2))
    else:
        getattr(installer, args.action)()


if __name__ == "__main__":
    main()
