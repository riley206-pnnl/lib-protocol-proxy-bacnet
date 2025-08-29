# Local Tests

This directory contains local test files that are not tracked by Git.

## Purpose
- Store experimental test scripts
- Keep development/debugging tests local
- Test integrated BACnet proxy functionality
- Network discovery testing

## Files in this directory
- `test_integrated_bacnet_proxy.py` - Test script for integrated BACnet proxy with network discovery

## Usage
All files in this directory are ignored by Git (see `.gitignore`). You can freely create and modify test files here without affecting the repository.

## Running Tests
```bash
# Run the integrated BACnet proxy test
python local_tests/test_integrated_bacnet_proxy.py
```

## Note
Files in this directory are for local development and testing only. Do not commit sensitive test data or configuration files.
