"""Initial

Revision ID: 001
Revises: 
Create Date: 2026-05-27 22:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('hashed_password', sa.String(), nullable=False),
        sa.Column('reset_token', sa.String(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True, default=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
    op.create_index(op.f('ix_users_reset_token'), 'users', ['reset_token'], unique=False)
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)

    # attacks table
    op.create_table(
        'attacks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('attack_type', sa.String(), nullable=True),
        sa.Column('symptoms', sa.JSON(), nullable=True),
        sa.Column('severity', sa.String(), nullable=True),
        sa.Column('mitre_id', sa.String(), nullable=True),
        sa.Column('description', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_attacks_attack_type'), 'attacks', ['attack_type'], unique=False)
    op.create_index(op.f('ix_attacks_id'), 'attacks', ['id'], unique=False)

    # consultation_history table
    op.create_table(
        'consultation_history',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('session_id', sa.String(), nullable=True),
        sa.Column('symptoms', sa.JSON(), nullable=True),
        sa.Column('target_system', sa.String(), nullable=True),
        sa.Column('detected_attacks', sa.JSON(), nullable=True),
        sa.Column('duration_ms', sa.Float(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_consultation_history_id'), 'consultation_history', ['id'], unique=False)
    op.create_index(op.f('ix_consultation_history_session_id'), 'consultation_history', ['session_id'], unique=True)


def downgrade():
    op.drop_index(op.f('ix_consultation_history_session_id'), table_name='consultation_history')
    op.drop_index(op.f('ix_consultation_history_id'), table_name='consultation_history')
    op.drop_table('consultation_history')
    
    op.drop_index(op.f('ix_attacks_id'), table_name='attacks')
    op.drop_index(op.f('ix_attacks_attack_type'), table_name='attacks')
    op.drop_table('attacks')
    
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.drop_index(op.f('ix_users_reset_token'), table_name='users')
    op.drop_index(op.f('ix_users_id'), table_name='users')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
