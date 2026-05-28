# Manual Test Plan

## 1. Unused codes export

**Setup:** prepare a codes CSV with more rows than your DJ list (e.g. 10 DJs, 15 codes).

| Step | Action | Expected result |
|------|--------|----------------|
| 1 | Upload DJ list, proceed to Step 2 | — |
| 2 | Upload codes file with 5 extra codes, fill in subject/body, click Preview | No error; preview shows 10 emails |
| 3 | Click **Send All Emails** and confirm | Emails send; progress bar reaches 100% |
| 4 | After send completes | **Export Unused Codes** button appears below the results |
| 5 | Click **Export Unused Codes** | `unused-codes.csv` downloads with 2 columns: `Release`, `Unused Code`; file contains exactly 5 rows |
| 6 | Open the CSV | Each unused code matches rows 11-15 of the original codes file |
| 7 | Run a second campaign where codes = DJs (exact match) | **Export Unused Codes** button does NOT appear |

---

## 2. Optional name column

**Setup:** prepare a DJ list CSV with only an email column (no name column).

| Step | Action | Expected result |
|------|--------|----------------|
| 1 | Upload the email-only CSV | Column selectors appear; Name Column dropdown includes `— no name column —` option |
| 2 | Select `— no name column —` for Name Column | — |
| 3 | Select the email column, click Next | No validation error |
| 4 | Complete Step 2 and click Preview | Preview shows emails with a blank name field; `{name}` placeholder in templates renders as empty string |
| 5 | Click **Send All Emails** | Emails send without errors |

---

## 3. Multi-release unused codes

**Setup:** add two releases; Release A has 3 extra codes, Release B has none.

| Step | Action | Expected result |
|------|--------|----------------|
| 1 | Configure both releases and click Preview | — |
| 2 | Send all emails | — |
| 3 | Inspect downloaded `unused-codes.csv` | Only rows for Release A appear; Release B produces no rows |

---

## 4. Edge cases

| Scenario | Expected result |
|----------|----------------|
| Codes file has blank rows mixed in | Warning banner mentions skipped rows; unused codes count is still correct (blanks excluded from both assigned and unused) |
| Generate a new preview after a send | **Export Unused Codes** button is hidden until the next send completes |
| Retry failed emails | Button remains visible; CSV still reflects the original unused codes from the preview |
