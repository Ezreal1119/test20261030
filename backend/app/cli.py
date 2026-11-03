import argparse

from app.config import ensure_admin_token, get_settings
from app.db import init_db
from app.services.device_auth import create_enrollment_token


def main() -> None:
    parser = argparse.ArgumentParser(description="DT610 verification lab commands")
    parser.add_argument("command", choices=["show-token", "issue-token"])
    args = parser.parse_args()
    init_db()
    ensure_admin_token()
    if args.command == "show-token":
        print(get_settings().admin_token)
        return
    issued = create_enrollment_token()
    print(issued["enrollment_token"])


if __name__ == "__main__":
    main()
