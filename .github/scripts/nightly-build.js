module.exports = async ({ github, context, core }) => {
  const repository = context.repo;
  const branches = await github.paginate(github.rest.repos.listBranches, {
    ...repository,
    per_page: 100,
  });

  for (const branch of branches.filter(({ name }) => ['main', 'develop'].includes(name))) {
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

      await github.rest.actions.createWorkflowDispatch({
        ...repository,
        workflow_id: workflow,
        ref: branch.name,
        ...(workflow === 'core.yml' ? { inputs: { sign_windows: false } } : {}),
      });
      core.info(`${workflow}: dispatched a full build for ${branch.name}.`);
    }
  }
};
