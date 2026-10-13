module.exports = async ({ github, context, core }) => {
  const builds = [
    ['core.yml', process.env.CORE_RUN_ID],
    ['gui.yml', process.env.GUI_RUN_ID],
    ['mobile.yml', process.env.MOBILE_RUN_ID],
  ];
  let commit;

  for (const [workflow, runId] of builds) {
    const { data: run } = await github.rest.actions.getWorkflowRun({
      ...context.repo,
      run_id: Number(runId),
    });
    const fullBuild = run.event === 'workflow_dispatch' ||
      (run.event === 'push' && run.head_branch.startsWith('releases/'));
    const nightly = run.path === '.github/workflows/nightly.yml' &&
      run.head_branch === 'main' && ['schedule', 'workflow_dispatch'].includes(run.event);
    if (run.conclusion !== 'success' ||
        !(nightly || (run.path === `.github/workflows/${workflow}` && fullBuild))) {
      throw new Error(`${workflow}: run ${runId} must be a successful full build.`);
    }
    if (commit && run.head_sha !== commit) {
      throw new Error('Core, GUI and Mobile must be built from the same commit.');
    }
    commit = run.head_sha;
    core.info(`${workflow}: validated full build ${runId} at ${commit}.`);
  }
};
