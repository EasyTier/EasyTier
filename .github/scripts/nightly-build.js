const { setTimeout } = require('node:timers/promises');

module.exports = async ({ github, context, core, sleep = setTimeout }) => {
  const repository = context.repo;
  const branches = await github.paginate(github.rest.repos.listBranches, {
    ...repository,
    per_page: 100,
  });

  for (const branch of branches.filter(({ name }) => name === 'main')) {
    const pending = new Map();
    for (const workflow of ['core.yml', 'gui.yml', 'mobile.yml', 'test.yml']) {
      const { data } = await github.rest.actions.listWorkflowRuns({
        ...repository,
        workflow_id: workflow,
        branch: branch.name,
        event: 'workflow_dispatch',
        status: 'success',
        per_page: 1,
      });
      if (data.workflow_runs[0]?.head_sha === branch.commit.sha) {
        core.info(`${workflow}: ${branch.name} is already built successfully.`);
        continue;
      }

      const { data: run } = await github.rest.actions.createWorkflowDispatch({
        ...repository,
        workflow_id: workflow,
        ref: branch.name,
        // This API version returns the dispatched run ID.
        headers: { 'X-GitHub-Api-Version': '2026-03-10' },
        ...(workflow === 'core.yml' ? { inputs: { sign_windows: false } } : {}),
      });
      pending.set(workflow, { id: run.workflow_run_id, attempt: 1 });
      core.info(`${workflow}: dispatched ${run.html_url} for ${branch.name}.`);
    }

    // GITHUB_TOKEN dispatches do not trigger downstream workflow_run jobs.
    // Wait here so publication and retries do not depend on those events.
    while (pending.size) {
      for (const [workflow, build] of pending) {
        const { data: run } = await github.rest.actions.getWorkflowRun({
          ...repository, run_id: build.id,
        });
        if (run.head_sha !== branch.commit.sha) {
          throw new Error(`${workflow}: main changed while dispatching; run Nightly again.`);
        }
        // A rerun request can return before the new attempt becomes visible.
        if (run.run_attempt < build.attempt || run.status !== 'completed') continue;
        if (run.conclusion === 'success') {
          core.info(`${workflow}: run ${build.id} succeeded.`);
          pending.delete(workflow);
        } else if (run.conclusion === 'failure' && run.run_attempt === 1) {
          await github.rest.actions.reRunWorkflowFailedJobs({
            ...repository, run_id: build.id,
          });
          build.attempt = 2;
          core.info(`${workflow}: retrying failed jobs in run ${build.id}.`);
        } else {
          throw new Error(`${workflow}: run ${build.id} finished with ${run.conclusion}.`);
        }
      }
      if (pending.size) {
        core.info(`Waiting for ${[...pending.keys()].join(', ')} at ${branch.commit.sha}.`);
        await sleep(60_000);
      }
    }
    return branch.commit.sha;
  }
};
