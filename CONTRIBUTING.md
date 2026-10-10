# Contributing

Thanks for helping improve Retrievo. This project handles potentially valuable user data, so safety and honest recovery guarantees come first.

## Before opening a pull request

- Keep source-device access read-only.
- Never write recovered output to the scanned source.
- Add tests using synthetic data or legally usable public fixtures; do not commit personal, private, or unreleased recovered files.
- Document format limitations and avoid claiming support beyond tested cases.
- Run the test suite: `python -m unittest discover -s tests -v`.

## Bug reports

Include your operating system, Python version, source type (image or raw device), the format involved, and the steps to reproduce. Do not attach disk images or recovered personal data. Remove usernames, serial numbers, and other identifying information from logs before sharing.

## Pull requests

Keep changes focused, explain the user-visible effect, and include tests for recovery behavior and error handling where applicable.
