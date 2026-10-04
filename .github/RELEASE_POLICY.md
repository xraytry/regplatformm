# Publication policy

The publication workflow runs only through `workflow_dispatch`. Its required
boolean `publish` input defaults to `false`, and every job independently checks
both the manual event and the typed boolean confirmation. Pushes (including a
merge into `main`), pull requests, tags, schedules and chained workflow events
cannot start this workflow. Dispatching with the default input runs no jobs.

Setting `publish` to `true` explicitly enables the existing image pushes,
GitHub Release writes and Cloudflare Worker deployment. Only do this with
separate, explicit authorization for those operations. A rerun of an already
authorized manual publication retains its original `true` input and can publish
again; do not use rerun for ordinary validation. This change does not disable
those commands or claim that external integrations have been audited.

`go test ./...` includes the workflow contract tests. They parse the complete
workflow set, check the manual gate and least permissions, and reject automatic
events, missing gates, unsafe confirmation defaults and new chained workflows.
These are offline checks and never execute a GitHub Actions job or a deployment.
