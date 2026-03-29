# Threat Intel Sync

Automated ingestion of AI/LLM-related threat intelligence from public feeds into DRAKO-ABSS advisory format.

## Feeds

| Source | Type | API Key | Description |
|--------|------|---------|-------------|
| **AlienVault OTX** | Pulse search | `OTX_API_KEY` env var | AI/LLM security pulses with quality gate |
| **abuse.ch URLhaus** | Recent URLs | None required | Malicious URLs targeting AI infrastructure |

## Quality Gate (OTX)

Pulses must pass **all three** checks to be accepted:

1. **Author reputation**: `subscriber_count >= 10` (configurable)
2. **Concrete indicators**: `indicator_count >= 1` (configurable)
3. **AI relevance**: At least one tag matches the AI keyword whitelist

Rejected pulses are logged at `DEBUG` level — no silent drops.

## Usage

```bash
# Full sync (both feeds)
python sync_all.py

# Single feed
python sync_all.py --source otx
python sync_all.py --source abusech

# Preview without writing
python sync_all.py --dry-run
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OTX_API_KEY` | Recommended | AlienVault OTX API key (unauthenticated requests are rate-limited) |

## Output

Advisories are written as YAML files to `output/` in DRAKO-ABSS format.

**This is a staging directory** — output does NOT feed into the SDK advisory loader
(`sdk/src/drako/advisories.py`). External advisories require manual review and
`drako_rules` mapping before promotion to the SDK corpus.

### ID Namespaces

| Feed | ID Format | Example |
|------|-----------|---------|
| OTX | `DRAKO-ABSS-EXT-{pulse_id}` | `DRAKO-ABSS-EXT-abc12345` |
| URLhaus | `DRAKO-ABSS-EXT-AH-{entry_id}` | `DRAKO-ABSS-EXT-AH-12345678` |

## Deduplication

A `state.json` file tracks previously seen advisory IDs across runs.
On-disk advisories in `output/` are also checked to prevent duplicates.

## CI Integration

The GitHub Actions workflow (`.github/workflows/threat-intel-sync.yml`) runs daily at 06:00 UTC.
Manual dispatch supports `--source` and `--dry-run` parameters.

## Configuration

Edit `config.yaml` to adjust:

- Feed URLs and timeouts
- Quality gate thresholds
- AI-relevant tag whitelist
- AI infrastructure domain list
- Output limits

## Tests

```bash
pip install -r requirements.txt
pip install pytest pytest-asyncio
pytest test_sync.py -v
```
