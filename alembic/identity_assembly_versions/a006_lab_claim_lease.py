"""Add the nullable worker-stamped lab claim lease after a005.

Revision ID: a006_lab_claim_lease
Revises: a005_erp_completion_checkpoint
"""

from alembic import op
from app.maintenance import fresh_product as fresh
from app.maintenance import lab_claim_lease_transition as lab_claim
from app.maintenance import product_adoption as product

revision = "a006_lab_claim_lease"
down_revision = "a005_erp_completion_checkpoint"
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    if fresh._issued(connection) is not None:
        fresh._apply(connection, revision)
        return
    try:
        entry = product._consume_lab_claim_lease_transition(connection)
        lab_claim._apply_lab_claim_lease_transition(connection, entry)
        product._record_lab_claim_lease_transition(connection, entry)
    except BaseException as error:
        product._poison(connection, None)
        if not isinstance(error, Exception):
            raise
        raise product.ProductAdoptionRefused("Academy a006 refused; root rollback required") from None


def downgrade():
    raise product.ProductAdoptionRefused("Academy a006 downgrade unsupported; root rollback required")
