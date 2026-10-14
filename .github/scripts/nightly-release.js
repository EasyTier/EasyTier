const fs = require('node:fs/promises');
const path = require('node:path');

const workflows = ['core', 'gui', 'mobile', 'test'];

function releaseNotes(repository, baseline, sha, commits, runs) {
  const url = `https://github.com/${repository.owner}/${repository.repo}`;
  const changes = [...commits]
    .sort((a, b) => Date.parse(b.commit.committer.date) - Date.parse(a.commit.committer.date))
    .map(commit => {
      const date = new Date(commit.commit.committer.date).toISOString().slice(0, 10);
      const subject = commit.commit.message.split('\n')[0];
      return `- ${date} — ${subject} ([${commit.sha.slice(0, 7)}](${commit.html_url}))`;
    });
  return [
    '# EasyTier Nightly',
    '',
    'Development builds from `main`. This prerelease and its download URLs are updated in place.',
    '',
    `Commit: [${sha}](${url}/commit/${sha})`,
    `Builds: ${runs.map(run => `[${run.name}](${run.html_url})`).join(' · ')}`,
    '',
    `## Changes since [${baseline.tag_name}](${baseline.html_url})`,
    '',
    'Dates are commit dates in UTC, newest first.',
    '',
    ...changes,
    ...(changes.length ? [] : ['No changes since this version.']),
    '',
    `[Full changelog](${url}/compare/${baseline.tag_name}...${sha})`,
    '',
  ].join('\n');
}

async function prepare({ github, context, core, sha }) {
  const repository = context.repo;
  const { data: branch } = await github.rest.repos.getBranch({ ...repository, branch: 'main' });
  sha ||= context.payload.workflow_run?.head_sha || branch.commit.sha;
  const { data: ancestry } = await github.rest.repos.compareCommitsWithBasehead({
    ...repository, basehead: `${sha}...${branch.commit.sha}`, per_page: 1,
  });
  if (!['ahead', 'identical'].includes(ancestry.status)) {
    core.info(`${sha} is no longer on main.`);
    return null;
  }

  // Listing releases also finds an unfinished draft from the first upload.
  const releases = await github.paginate(github.rest.repos.listReleases, {
    ...repository, per_page: 100,
  });
  const release = releases.find(item => item.tag_name === 'nightly');
  if (release?.immutable) throw new Error('The nightly release must allow asset and tag updates.');
  if (release && !release.draft) {
    const { data: comparison } = await github.rest.repos.compareCommitsWithBasehead({
      ...repository, basehead: `nightly...${sha}`, per_page: 1,
    });
    if (!['ahead', 'identical'].includes(comparison.status)) {
      core.info('A newer nightly is already available; skipping this older build.');
      return null;
    }
    if (comparison.status === 'identical' && release.body?.includes(`Commit: [${sha}]`)) {
      core.info(`${sha} is already published.`);
      return null;
    }
  }

  const runs = [];
  const artifacts = {};
  for (const workflow of workflows) {
    const { data } = await github.rest.actions.listWorkflowRuns({
      ...repository,
      workflow_id: `${workflow}.yml`,
      branch: 'main',
      head_sha: sha,
      event: 'workflow_dispatch',
      status: 'success',
      per_page: 1,
    });
    const run = data.workflow_runs[0];
    if (!run || run.head_sha !== sha || run.head_branch !== 'main' ||
        run.event !== 'workflow_dispatch' || run.conclusion !== 'success') {
      core.info(`Waiting for a successful full ${workflow} build at ${sha}.`);
      return null;
    }
    runs.push(run);
    if (workflow === 'test') continue;
    const uploaded = await github.paginate(github.rest.actions.listWorkflowRunArtifacts, {
      ...repository, run_id: run.id, per_page: 100,
    });
    // Reruns can retain same-name artifacts from earlier attempts. Select the
    // newest ID, matching download-artifact's latest:true lookup.
    const byName = new Map();
    for (const artifact of uploaded) {
      if (!/^(easytier-[\w.-]+|Easytier-Magisk)$/.test(artifact.name)) continue;
      if (!byName.has(artifact.name) || artifact.id > byName.get(artifact.name).id) {
        byName.set(artifact.name, artifact);
      }
    }
    const files = [...byName.values()];
    if (!files.length || files.some(artifact => artifact.expired)) {
      throw new Error(`${workflow}: build artifacts are missing or expired.`);
    }
    artifacts[workflow] = files.map(artifact => ({ id: artifact.id, name: artifact.name }));
  }

  // Version releases may be published by a maintainer from a bot-created draft,
  // and may themselves be prereleases. Neither author nor /releases/latest
  // identifies the last manually published version reliably.
  const baseline = releases.filter(item => !item.draft && /^v\d+\.\d+\.\d+(?:[-+].*)?$/.test(item.tag_name))
    .sort((a, b) => Date.parse(b.published_at) - Date.parse(a.published_at))[0];
  if (!baseline) throw new Error('No published version release found for the nightly changelog.');
  const commits = await github.paginate(github.rest.repos.compareCommitsWithBasehead, {
    ...repository, basehead: `${baseline.tag_name}...${sha}`, per_page: 100,
  }, response => response.data.commits);

  return {
    sha,
    release_id: release?.id,
    runs: Object.fromEntries(workflows.map((workflow, index) => [workflow, runs[index].id])),
    artifacts,
    body: releaseNotes(repository, baseline, sha, commits, runs),
  };
}

async function publish({ github, context, core, build, directory }) {
  const repository = context.repo;
  const names = Object.values(build.artifacts).flat().map(artifact => `${artifact.name}.zip`).sort();
  const files = (await fs.readdir(directory)).sort();
  if (!names.length || JSON.stringify(files) !== JSON.stringify(names)) {
    throw new Error('Packaged files do not match the selected nightly artifacts.');
  }
  for (const name of files) {
    if (!(await fs.stat(path.join(directory, name))).size) throw new Error(`Empty asset: ${name}`);
  }

  const releases = await github.paginate(github.rest.repos.listReleases, {
    ...repository, per_page: 100,
  });
  let release = releases.find(item => item.tag_name === 'nightly');
  if (release?.immutable) throw new Error('The nightly release must allow asset and tag updates.');
  if ((release?.id || undefined) !== build.release_id) {
    throw new Error('The nightly release changed during preparation; run the workflow again.');
  }
  if (!release) {
    const { data } = await github.rest.repos.createRelease({
      ...repository, tag_name: 'nightly', target_commitish: build.sha,
      name: 'Nightly', draft: true, prerelease: true, make_latest: 'false',
    });
    release = data;
  }

  const previousAssets = await github.paginate(github.rest.repos.listReleaseAssets, {
    ...repository, release_id: release.id, per_page: 100,
  });
  for (const name of files) {
    const previous = previousAssets.find(asset => asset.name === name);
    if (previous) {
      await github.rest.repos.deleteReleaseAsset({ ...repository, asset_id: previous.id });
    }
    await github.rest.repos.uploadReleaseAsset({
      ...repository, release_id: release.id, name,
      data: await fs.readFile(path.join(directory, name)),
      headers: { 'content-type': 'application/zip' },
    });
  }
  // Remove retired platforms only after all replacement assets are uploaded.
  for (const asset of previousAssets.filter(asset => !files.includes(asset.name))) {
    await github.rest.repos.deleteReleaseAsset({ ...repository, asset_id: asset.id });
  }

  // A new draft does not necessarily have a tag yet.
  try {
    await github.rest.git.getRef({ ...repository, ref: 'tags/nightly' });
    await github.rest.git.updateRef({ ...repository, ref: 'tags/nightly', sha: build.sha, force: true });
  } catch (error) {
    if (error.status !== 404) throw error;
    await github.rest.git.createRef({ ...repository, ref: 'refs/tags/nightly', sha: build.sha });
  }
  await github.rest.repos.updateRelease({
    ...repository, release_id: release.id, name: 'Nightly', body: build.body,
    target_commitish: build.sha,
    draft: false, prerelease: true, make_latest: 'false',
  });
  core.info(`Updated nightly at ${build.sha}: ${release.html_url}`);
}

module.exports = { prepare, publish, releaseNotes };
