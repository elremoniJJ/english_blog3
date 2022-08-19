"""added relationship between Posts and Users 3

Revision ID: 3404e9e6162c
Revises: 4208182d0d66
Create Date: 2022-08-19 13:44:19.008207

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3404e9e6162c'
down_revision = '4208182d0d66'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_foreign_key(None, 'posts', 'users', ['poster_id'], ['id'])
    op.drop_column('posts', 'author')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('posts', sa.Column('author', sa.VARCHAR(length=50), nullable=True))
    op.drop_constraint(None, 'posts', type_='foreignkey')
    # ### end Alembic commands ###
