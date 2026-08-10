from app.models.account_token import AccountToken  # noqa: F401
from app.models.admissions import Applicant  # noqa: F401
from app.models.announcement import Announcement  # noqa: F401
from app.models.assessment import Activity, Question, QuestionBank, Score, Submission  # noqa: F401
from app.models.attempt import ActivityAttempt  # noqa: F401
from app.models.bookmark import ChapterBookmark, ChapterNote  # noqa: F401
from app.models.certificate import Certificate  # noqa: F401
from app.models.class_session import ClassSession  # noqa: F401
from app.models.cohort import Cohort, Enrollment  # noqa: F401
from app.models.completion import CourseCompletion  # noqa: F401
from app.models.course import Chapter, Course  # noqa: F401
from app.models.email_outbox import EmailOutbox  # noqa: F401
from app.models.entrance_defaults import TenantEntranceDefaults  # noqa: F401
from app.models.lab import LabInstance, LabTemplate  # noqa: F401
from app.models.learning_event import LearningEvent  # noqa: F401
from app.models.notification import Notification  # noqa: F401
from app.models.offering import CourseOffering  # noqa: F401
from app.models.onboarding import OnboardingTask  # noqa: F401
from app.models.pacing import OfferingActivity  # noqa: F401
from app.models.platform_settings import PlatformSetting  # noqa: F401
from app.models.prerequisite import CoursePrerequisite  # noqa: F401
from app.models.reading import ChapterRead  # noqa: F401
from app.models.reminder import ReminderLog, ReminderPreference  # noqa: F401
from app.models.success_queue import SuccessQueueEntry  # noqa: F401
from app.models.tenant import Tenant, TenantDomain  # noqa: F401
from app.models.track import CohortTrack, Track, TrackCourse  # noqa: F401
