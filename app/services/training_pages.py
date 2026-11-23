"""Public course copy projected from Learning's listed-course authority.

This is presentation copy, not a second catalogue or an eligibility policy.
Only courses returned by Learning.public_catalog can acquire a public page.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


@dataclass(frozen=True)
class TrainingCopy:
    course_title: str
    slug: str
    heading: str
    description: str


@dataclass(frozen=True)
class TrainingPage:
    copy: TrainingCopy
    chapter_count: int
    management: bool

    @property
    def path(self) -> str:
        if self.copy.course_title == "Fiber Engineering":
            return "/fibre-optic-training"
        return f"/training/{self.copy.slug}"

    @property
    def canonical_url(self) -> str:
        return f"https://academy.dotmac.io{self.path}"


COURSE_COPY: tuple[TrainingCopy, ...] = (
    TrainingCopy(
        "Fiber Engineering",
        "fibre-optic-training",
        "Fibre optic training in Nigeria",
        "Explore fibre optic training through Dotmac Academy's Fiber Engineering course, with "
        "chapter tests and a final assessment.",
    ),
    TrainingCopy(
        "Fiber Project Management",
        "fibre-project-management",
        "Fibre project management training",
        "Study fibre project management with Dotmac Academy's technical programme in Nigeria. Apply "
        "for a cohort and complete assessed training.",
    ),
    TrainingCopy(
        "Network Foundation",
        "networking-fundamentals",
        "Networking fundamentals training in Nigeria",
        "Build your networking foundation with Dotmac Academy's Network Foundation course, chapter "
        "tests and a final assessment.",
    ),
    TrainingCopy(
        "Routing & Switching",
        "routing-and-switching",
        "Routing and switching training in Nigeria",
        "Explore routing and switching training at Dotmac Academy. Join the technical programme "
        "through application and a placement assessment.",
    ),
    TrainingCopy(
        "Wireless & Radio",
        "wireless-and-radio",
        "Wireless networking and radio training",
        "Explore wireless networking and radio training through Dotmac Academy's assessed technical "
        "programme in Nigeria.",
    ),
    TrainingCopy(
        "Network Support",
        "network-support",
        "Network support training in Nigeria",
        "Study network support through Dotmac Academy's technical programme, with chapter tests and "
        "a final assessment.",
    ),
    TrainingCopy(
        "NOC Operations",
        "noc-operations",
        "Network operations centre training",
        "Explore NOC operations training at Dotmac Academy in Nigeria. Study network operations "
        "through a chaptered, assessed technical course.",
    ),
    TrainingCopy(
        "Technical Support",
        "technical-support",
        "IT technical support training in Nigeria",
        "Explore IT technical support training at Dotmac Academy, with chaptered study, practice "
        "tests and a final assessment.",
    ),
    TrainingCopy(
        "Service Delivery & Helpdesk",
        "service-delivery-and-helpdesk",
        "IT helpdesk and service delivery training",
        "Study service delivery and IT helpdesk operations through Dotmac Academy's assessed "
        "technical programme in Nigeria.",
    ),
    TrainingCopy(
        "Power & Site Infrastructure Operations",
        "power-and-site-infrastructure",
        "Telecom power and site infrastructure training",
        "Explore power and site infrastructure operations training at Dotmac Academy, with chapter "
        "tests and a final assessment.",
    ),
    TrainingCopy(
        "Regulatory & Compliance Operations",
        "regulatory-and-compliance",
        "Telecom regulatory compliance training",
        "Explore regulatory and compliance operations through Dotmac Academy's technical training "
        "programme in Nigeria.",
    ),
    TrainingCopy(
        "Commercial & Customer Operations",
        "commercial-and-customer-operations",
        "Telecom commercial and customer operations training",
        "Explore commercial and customer operations training through Dotmac Academy's assessed "
        "technical programme in Nigeria.",
    ),
    TrainingCopy(
        "Communication & Reporting for Managers",
        "communication-and-reporting",
        "Communication and reporting training for managers",
        "Explore Dotmac Academy's self-paced communication and reporting course for managers, with "
        "chapter tests and a final assessment.",
    ),
    TrainingCopy(
        "Customer Experience & Service Management",
        "customer-experience",
        "Customer experience and service management training",
        "Study customer experience and service management with Dotmac Academy's self-paced "
        "professional development course.",
    ),
    TrainingCopy(
        "Decision Making & Problem Solving",
        "decision-making",
        "Decision making and problem solving training",
        "Explore decision making and problem solving with Dotmac Academy's self-paced management "
        "course for teams and individuals.",
    ),
    TrainingCopy(
        "Finance for Non-Financial Managers",
        "finance-for-managers",
        "Finance for non-financial managers in Nigeria",
        "Explore finance for non-financial managers through Dotmac Academy's self-paced, assessed "
        "professional development course.",
    ),
    TrainingCopy(
        "Leading a Team: First-Time Manager Essentials",
        "first-time-manager",
        "First-time manager and team leadership training",
        "Explore team leadership and first-time manager essentials with Dotmac Academy's self-paced management course.",
    ),
    TrainingCopy(
        "Managing with Data & KPIs",
        "data-and-kpis",
        "Managing with data and KPIs training",
        "Explore data-driven management and KPIs through Dotmac Academy's self-paced course for "
        "managers and professionals.",
    ),
    TrainingCopy(
        "Project Management Essentials",
        "project-management",
        "Project management essentials training",
        "Study project management essentials with Dotmac Academy's self-paced professional "
        "development course for teams and individuals.",
    ),
    TrainingCopy(
        "Sales Essentials",
        "sales-essentials",
        "Sales skills training in Nigeria",
        "Explore sales essentials with Dotmac Academy's self-paced professional development course, "
        "chapter tests and a final assessment.",
    ),
    TrainingCopy(
        "Vendor & Procurement Management",
        "vendor-and-procurement",
        "Vendor and procurement management training",
        "Explore vendor and procurement management with Dotmac Academy's self-paced course for "
        "managers and professionals.",
    ),
)


def training_page(*, title: str, chapter_count: int, discipline: str) -> TrainingPage | None:
    """Attach reviewed copy to a current public course; unknown courses stay unlinked."""
    copy = next((copy for copy in COURSE_COPY if copy.course_title == title), None)
    if copy is None:
        return None
    return TrainingPage(copy=copy, chapter_count=chapter_count, management=discipline == "management")


def public_training_pages(db: Session, *, tenant_id: UUID) -> tuple[TrainingPage, ...]:
    """Use the same tenant-scoped listed/published selector as the public catalogue."""
    import dotmac_learning as learning

    pages: list[TrainingPage] = []
    for item in learning.public_catalog(db, tenant_id=tenant_id):
        page = training_page(
            title=item.course.title,
            chapter_count=item.chapter_count,
            discipline=item.course.discipline,
        )
        if page is not None:
            pages.append(page)
    return tuple(pages)
