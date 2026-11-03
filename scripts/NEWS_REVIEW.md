# Daily news review

The Codex heartbeat **Review fridge attacks daily** runs at 08:30 America/New_York in the originating chat. It needs the local Codex execution environment to be available. GitHub's Shodan workflow is independent of the local machine.

1. Synchronize `main` safely. Do not overwrite uncommitted work or force push. Use a separate checkout when needed.
2. Search news and primary sources for Danfoss/StoreView/refrigeration cyberattacks since the last completed review. Read the actual reports. Prefer CERT-FR, vendor advisories, direct retailer statements, and established reporting such as AP and Reuters. Do not treat inaccessible sources or search failures as a completed review.
3. Distinguish incident dates from publication dates. For approximate dates, retain a clear `dateLabel`. Distinguish suspected incidents from confirmed compromises, and avoid attributing the US military incidents to Danfoss without evidence.
4. Add unique, sourced incidents to `site/data/incidents.json`, in ascending date order. `major: true` is reserved for substantial new waves disrupting refrigeration at multiple sites. Continuing activity within the same wave or retrospective articles do not reset the counter. `date` is the incident date used by the UTC calendar-day counter. For overnight waves, use the morning when disruption became apparent and describe the range in `dateLabel`.
5. Update `site/data/status.json` after successful review. The initial **No.** is an editorial assessment, not an automated vulnerability verdict. Lack of new headlines never automatically changes it to Yes. Update page wording/date ranges if the timeline extends beyond 2026.
6. Append a compact entry to `site/data/reviews.json` with review date, source URLs checked, and outcome, including no-new-incident reviews. Keep descriptions short and paraphrased. A review date is evidence of actual completed work, not a daily timer.
7. Check the latest GitHub Actions run and `site/data/shodan.json`. Never retrieve or log credentials. Do not duplicate the daily collection. Never contact discovered controllers.
8. Run `python3 -m unittest discover -s tests -v` and `python3 scripts/validate.py`. Inspect the diff. Commit only relevant changes, push `main`, and verify the Pages deployment. Handle remote updates without force-pushing.
9. Notify the user only for meaningful new incidents, corrections, failures, or required action. Routine no-change reviews are quiet.

Research is not proof that no attack occurred. Sources can lag events, and the visible review timestamp must remain honest.
