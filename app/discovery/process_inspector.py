def process_info(record):
    """Missing or inaccessible process fields are evidence gaps, not scan failures."""
    try:
        pid = int(record.get('OwningProcess') or record.get('pid') or 0)
    except (ValueError, TypeError):
        pid = 0
    return dict(pid=pid, process=record.get('ProcessName') or 'Unknown',
                executable=record.get('ExecutablePath') or None,
                windows_services=record.get('Services') or [],
                process_detail='Available' if record.get('ProcessName') else 'Unavailable: access denied or process exited')
