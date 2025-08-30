"""Initial migration for beekeeper schema

Revision ID: a0f3e9fb3bc7
Revises: 
Create Date: 2025-08-29 22:45:04.847148

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'a0f3e9fb3bc7'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create beekeeper schema
    op.execute('CREATE SCHEMA IF NOT EXISTS beekeeper')
    
    # Create users table
    op.create_table('users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=255), nullable=True),
        sa.Column('hashed_password', sa.String(length=255), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('is_superuser', sa.Boolean(), nullable=True),
        sa.Column('is_verified', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        schema='beekeeper'
    )
    op.create_index(op.f('ix_beekeeper_users_id'), 'users', ['id'], unique=False, schema='beekeeper')
    op.create_index(op.f('ix_beekeeper_users_email'), 'users', ['email'], unique=True, schema='beekeeper')
    
    # Create tokens table
    op.create_table('tokens',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('token', sa.String(length=500), nullable=False),
        sa.Column('jti', sa.String(length=255), nullable=True),
        sa.Column('token_type', sa.String(length=50), nullable=False),
        sa.Column('expires_at', sa.BigInteger(), nullable=False),
        sa.Column('is_revoked', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['beekeeper.users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='beekeeper'
    )
    op.create_index(op.f('ix_beekeeper_tokens_id'), 'tokens', ['id'], unique=False, schema='beekeeper')
    op.create_index(op.f('ix_beekeeper_tokens_token'), 'tokens', ['token'], unique=False, schema='beekeeper')
    op.create_index(op.f('ix_beekeeper_tokens_jti'), 'tokens', ['jti'], unique=True, schema='beekeeper')
    
    # Create verification_tokens table
    op.create_table('verification_tokens',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('token', sa.String(length=255), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['beekeeper.users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='beekeeper'
    )
    op.create_index(op.f('ix_beekeeper_verification_tokens_id'), 'verification_tokens', ['id'], unique=False, schema='beekeeper')
    op.create_index(op.f('ix_beekeeper_verification_tokens_token'), 'verification_tokens', ['token'], unique=True, schema='beekeeper')
    
    # Create password_reset_tokens table
    op.create_table('password_reset_tokens',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('token', sa.String(length=255), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['beekeeper.users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema='beekeeper'
    )
    op.create_index(op.f('ix_beekeeper_password_reset_tokens_id'), 'password_reset_tokens', ['id'], unique=False, schema='beekeeper')
    op.create_index(op.f('ix_beekeeper_password_reset_tokens_token'), 'password_reset_tokens', ['token'], unique=True, schema='beekeeper')
    
    # Create social_accounts table
    op.create_table('social_accounts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('provider', sa.String(length=50), nullable=False),
        sa.Column('provider_user_id', sa.String(length=255), nullable=False),
        sa.Column('access_token', sa.String(length=500), nullable=True),
        sa.Column('refresh_token', sa.String(length=500), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['beekeeper.users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'provider', 'provider_user_id', name='unique_user_provider_account'),
        schema='beekeeper'
    )
    op.create_index(op.f('ix_beekeeper_social_accounts_id'), 'social_accounts', ['id'], unique=False, schema='beekeeper')


def downgrade() -> None:
    # Drop tables in reverse order
    op.drop_index(op.f('ix_beekeeper_social_accounts_id'), table_name='social_accounts', schema='beekeeper')
    op.drop_table('social_accounts', schema='beekeeper')
    
    op.drop_index(op.f('ix_beekeeper_password_reset_tokens_token'), table_name='password_reset_tokens', schema='beekeeper')
    op.drop_index(op.f('ix_beekeeper_password_reset_tokens_id'), table_name='password_reset_tokens', schema='beekeeper')
    op.drop_table('password_reset_tokens', schema='beekeeper')
    
    op.drop_index(op.f('ix_beekeeper_verification_tokens_token'), table_name='verification_tokens', schema='beekeeper')
    op.drop_index(op.f('ix_beekeeper_verification_tokens_id'), table_name='verification_tokens', schema='beekeeper')
    op.drop_table('verification_tokens', schema='beekeeper')
    
    op.drop_index(op.f('ix_beekeeper_tokens_jti'), table_name='tokens', schema='beekeeper')
    op.drop_index(op.f('ix_beekeeper_tokens_token'), table_name='tokens', schema='beekeeper')
    op.drop_index(op.f('ix_beekeeper_tokens_id'), table_name='tokens', schema='beekeeper')
    op.drop_table('tokens', schema='beekeeper')
    
    op.drop_index(op.f('ix_beekeeper_users_email'), table_name='users', schema='beekeeper')
    op.drop_index(op.f('ix_beekeeper_users_id'), table_name='users', schema='beekeeper')
    op.drop_table('users', schema='beekeeper')
    
    # Drop schema
    op.execute('DROP SCHEMA IF EXISTS beekeeper CASCADE')