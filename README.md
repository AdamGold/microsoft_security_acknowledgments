This script creates a CSV file of all [Microsoft published vulnerabilities](https://portal.msrc.microsoft.com/en-us/security-guidance/acknowledgments).
It does so by sending concurrent requests to retrieve all vulnerabilities from 2015 to 2020. For each vulnerability, it sends another request the URL of its reference (which contains more information about the vulnerability) and then writes everything to a CSV file.

## Installation & Usage

This package uses poetry for packaging.

```python
pip install poetry
poetry run python -m src.main
```
