"""Initial normalized forensic schema."""
from pathlib import Path
import re

from alembic import op

revision = "0001"
down_revision = None


def upgrade():
    for statement in Path(__file__).with_name("0001_schema.sql").read_text().split(";"):
        if statement.strip():
            op.execute(statement)


def downgrade():
    schema = Path(__file__).with_name("0001_schema.sql").read_text()
    for name in reversed(re.findall(r"CREATE TABLE (\w+)", schema)):
        op.drop_table(name)
