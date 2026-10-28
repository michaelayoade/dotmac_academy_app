"""Rebind retained historical rows after independently sealed Learning import.

Revision ID: a004_retained_learning_refs
Revises: a003_account_token_identity
"""

from alembic import op
from app.maintenance import product_adoption as product
from app.maintenance import retained_transition as retained

revision = "a004_retained_learning_refs"
down_revision = "a003_account_token_identity"
branch_labels = None
depends_on = "lr_0007_enrollment_state_policy"


def upgrade():
    connection = op.get_bind()
    try:
        entry = product._consume_retained_transition(connection)
        retained._apply_retained_transition(connection, entry)
        product._record_retained_transition(connection, entry)
    except BaseException as error:
        product._poison(connection, None)
        if not isinstance(error, Exception):
            raise
        raise product.ProductAdoptionRefused("Academy a004 refused; root rollback required") from None


def downgrade():
    raise product.ProductAdoptionRefused("Academy a004 downgrade unsupported; root rollback required")
