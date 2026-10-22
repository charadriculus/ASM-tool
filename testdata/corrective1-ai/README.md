# Corrective 1 AI configuration fixtures

`config_operational_without_ai.yml` is a derived positive-behavior fixture copied from the immutable `testdata/phase1/config_operational.yml`. The derivation removes only the `modules.ai_review` entry and the top-level `ai_review` mapping; all unrelated settings and their values are retained. The original phase 1 fixture remains unchanged and is used as a rejection case.
