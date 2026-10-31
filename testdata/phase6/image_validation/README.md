# PNG validation source-oracle fixtures

These fixtures preserve the behavior of `utils/image_validation.py` from both
immutable 0.11.3 snapshots. `manifest.json` records both source SHA-256 values
and the Python oracle's acceptance/reason prefix for each fixture.

Rebuild or verify offline with:

```sh
python3 -B scripts/build_phase6_fixtures.py
python3 -B scripts/build_phase6_fixtures.py --check
```

The builder reads and compiles the reference source into a private namespace;
it does not import the legacy package. `--check` is read-only. The unusual
accepted cases are intentional: the source validates PNG chunk framing and
CRC plus a non-empty zlib result, but does not validate pixel encoding, chunk
ordering, or trailing bytes after the first zlib stream. No decoded-size cap is
added because full-page screenshots may be very tall.
