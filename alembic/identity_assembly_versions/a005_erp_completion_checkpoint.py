"""Preserve every raw completion ACK in inert checkpoint storage after a004.

Revision ID: a005_erp_completion_checkpoint
Revises: a004_retained_learning_refs
"""

from alembic import op
from app.maintenance import checkpoint_transition as checkpoint
from app.maintenance import product_adoption as product

revision = "a005_erp_completion_checkpoint"
down_revision = "a004_retained_learning_refs"
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    try:
        entry = product._consume_checkpoint_transition(connection)
        checkpoint._apply_checkpoint_transition(connection, entry)
        product._record_checkpoint_transition(connection, entry)
    except BaseException as error:
        product._poison(connection, None)
        if not isinstance(error, Exception):
            raise
        raise product.ProductAdoptionRefused("Academy a005 refused; root rollback required") from None


def downgrade():
    raise product.ProductAdoptionRefused("Academy a005 downgrade unsupported; root rollback required")
