"""Generate local-only database credentials; never overwrite existing configuration."""
from pathlib import Path
import secrets
root = Path(__file__).resolve().parents[1]
path = root / '.env'
if not path.exists():
    path.write_text('POSTGRES_PASSWORD=' + secrets.token_urlsafe(36) + '\n')
    path.chmod(0o600)
    print('Created private .env with random local database password.')
else:
    print('Existing .env preserved.')
