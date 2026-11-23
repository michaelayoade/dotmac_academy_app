# Public course search pages

The public catalogue links reviewed technical and management course copy to
public `/training/{slug}` pages. Fiber Engineering retains the existing
`/fibre-optic-training` URL to avoid a competing duplicate. The homepage and
catalogue describe the actual training subjects in their titles and descriptions.
No keyword meta tags, fabricated qualifications, fees or job guarantees are added.

Learning's tenant-scoped `public_catalog` remains the authority for listed,
published courses. `app/services/training_pages.py` owns presentation copy only;
it never loads private chapters, changes course records or grants access.
Course counts and discipline come from the current Learning projection. Unknown
course titles remain visible in the catalogue without a reviewed search-page
link. If a title changes, update the reviewed copy and verify the public links.

The catalogue, new training route and sitemap use that same projection. Unlisting
a course removes its new public training page and sitemap entry on the next
request; unknown or unavailable training slugs return 404. The existing static
programme and fibre pages remain informational pages with their existing URLs.
The new route must be declared in `app/assembly.py` as a public web entry route.
Authenticated `/courses/{slug}` learning content retains its access checks.

Technical pages explain assessment, intake availability and conditional free
training. Management pages link to the existing management enquiry form and make
no free-training promise. Their descriptions name the subject without inventing
specific curriculum objectives. Enrolment and admissions workflows are unchanged.

## Verification and rollout

Run `tests/test_training_pages.py` for isolated copy, template escaping,
enrolment-link and current-owner projection checks. These use fixture rendering,
not a second production renderer, and are not database integration evidence.
Full application CI with locked platform packages and hosted PostgreSQL is still
required, including anonymous HTTP checks of the mounted route and sitemap.
Before release, verify desktop/mobile rendering for both course types, unknown
slug 404, and that unpublished courses cannot be reached or listed in the sitemap.

After an authorized deployment, inspect `/sitemap.xml` and submit it in Search
Console. Request indexing of a sample course page. Search engines choose whether
to index or show the pages; source changes alone do not prove indexing or rankings.
