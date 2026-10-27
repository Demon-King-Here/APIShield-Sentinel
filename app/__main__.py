"""Supported single-process entry point: python -m app."""
import argparse
import uvicorn
from app.config import Settings


def main():
    parser = argparse.ArgumentParser(description='APIShield Sentinel: local administration and an API gateway')
    parser.add_argument('--check-config', action='store_true', help='Validate startup configuration without starting listeners or touching the database')
    arguments = parser.parse_args()
    try:
        settings = Settings()
        settings.validate()
    except (ValueError, OSError) as exc:
        parser.exit(2, f'Invalid APIShield configuration: {exc}\n')
    if arguments.check_config:
        print('Configuration valid. No database or listeners were opened.')
        return
    print(f'Dashboard: http://{settings.admin_host}:{settings.admin_port}')
    print('First setup code (only before account creation): see admin-setup-code.txt beside the configured database.')
    print('Stop with Ctrl+C. Run one process, without --reload or multiple workers.')
    from app.main import create_app
    uvicorn.run(create_app(settings), host=settings.admin_host, port=settings.admin_port,
                proxy_headers=False, access_log=False, server_header=False,
                limit_concurrency=100, timeout_keep_alive=5, timeout_graceful_shutdown=10)


if __name__ == '__main__':
    main()
