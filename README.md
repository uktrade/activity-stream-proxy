# activity-stream-proxy
Proxies requests from the activity-stream to the ZenDesk API

## Development Environment

```bash
python3 -m venv env
source ./env/bin/activate
```

## Tests

```bash
./tests.sh
```

## Managing Requirements

When adding a new library, first add it to requirements.in, then::

```bash
pip install pip-tools && \
pip-compile --output-file requirements.txt requirements.in && \
pip install -r requirements.txt
```
