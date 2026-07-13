# Privacy, consent, and withdrawal

Participation is voluntary. Before the first measured run, the coordinator
must explain what is collected, what may be shared, and how to withdraw.

The structured run record uses opaque participant, baseline, task, and oracle
IDs. It intentionally has no free-text field. The validator rejects
common identity, absolute-path, and credential patterns, but this is a safety
check rather than a complete anonymizer.

Do not place any of the following in a run record or public report:

- names, usernames, email addresses, student IDs, or private repository names;
- `.aoi/` contents, prompts, diffs, paths, commands, logs, or commit IDs;
- API keys, credentials, private endpoints, unpublished design details;
- private free-text feedback.

`consent.share_with_coordinator` permits privately sending the validated record
to the coordinator. `consent.aggregate` separately permits inclusion in a
de-identified aggregate. Both false values must be respected. Individual run
records are never public in this closed alpha; public reporting is aggregate-
only and must not break down results by participant.

Before enrollment, copy `withdrawal-private.template.csv` to the unmanaged
`withdrawal-private.csv`. Generate a unique high-entropy random code for each
participant and map it to the opaque participant ID in that private file. Do
not use sequential or guessable codes. The linkage stays with the coordinator
and never enters an analysis record or public report. Until the announced
analysis freeze, a participant can provide their code and request deletion. The
coordinator resolves the participant ID privately, removes all matching
records, then regenerates every aggregate.
