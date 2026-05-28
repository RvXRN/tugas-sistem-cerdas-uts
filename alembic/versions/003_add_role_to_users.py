"""Add role column to users table

Revision ID: 003
Revises: 002
Create Date: 2026-05-29 06:13:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade():
    # Tambah kolom role ke tabel users
    op.add_column(
        'users',
        sa.Column('role', sa.String(), nullable=False, server_default='user')
    )


def downgrade():
    op.drop_column('users', 'role')
