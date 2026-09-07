# Tests

```
pip install -r requirements.txt pytest
python -m pytest tests
```

`conftest.py` starts a hub in-process on a random port and drives nodes
one `step()` at a time; every key is generated inside the test. Nothing
touches `~/.natively` or a fixed port.
