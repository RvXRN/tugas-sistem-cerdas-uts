"""Add cve and ioc models

Revision ID: 002
Revises: 001
Create Date: 2026-05-27 22:15:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Create CVEs table
    op.create_table('cves',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('cve_id', sa.String(), nullable=True),
    sa.Column('vendor_project', sa.String(), nullable=True),
    sa.Column('product', sa.String(), nullable=True),
    sa.Column('vulnerability_name', sa.String(), nullable=True),
    sa.Column('date_added', sa.Date(), nullable=True),
    sa.Column('short_description', sa.Text(), nullable=True),
    sa.Column('required_action', sa.Text(), nullable=True),
    sa.Column('due_date', sa.Date(), nullable=True),
    sa.Column('cwes', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_cves_id'), 'cves', ['id'], unique=False)
    op.create_index(op.f('ix_cves_cve_id'), 'cves', ['cve_id'], unique=True)
    op.create_index(op.f('ix_cves_vendor_project'), 'cves', ['vendor_project'], unique=False)
    op.create_index(op.f('ix_cves_product'), 'cves', ['product'], unique=False)

    # Create IoCs table
    op.create_table('iocs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('indicator', sa.String(), nullable=True),
    sa.Column('indicator_type', sa.String(), nullable=True),
    sa.Column('reputation_score', sa.Float(), nullable=True),
    sa.Column('threat_label', sa.String(), nullable=True),
    sa.Column('threat_severity', sa.String(), nullable=True),
    sa.Column('data_source', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_iocs_id'), 'iocs', ['id'], unique=False)
    op.create_index(op.f('ix_iocs_indicator'), 'iocs', ['indicator'], unique=True)
    op.create_index(op.f('ix_iocs_indicator_type'), 'iocs', ['indicator_type'], unique=False)

def downgrade() -> None:
    op.drop_index(op.f('ix_iocs_indicator_type'), table_name='iocs')
    op.drop_index(op.f('ix_iocs_indicator'), table_name='iocs')
    op.drop_index(op.f('ix_iocs_id'), table_name='iocs')
    op.drop_table('iocs')

    op.drop_index(op.f('ix_cves_product'), table_name='cves')
    op.drop_index(op.f('ix_cves_vendor_project'), table_name='cves')
    op.drop_index(op.f('ix_cves_cve_id'), table_name='cves')
    op.drop_index(op.f('ix_cves_id'), table_name='cves')
    op.drop_table('cves')
