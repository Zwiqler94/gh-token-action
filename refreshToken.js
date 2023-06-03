const core = require('@actions/core');
const github = require('@actions/github');

async function run() {
    try {
        const octo = github.getOctokit({ token: await core.getIDToken('public_repo') });
        const s =  await octo.request('GET /repos/{owner}/{repo}/actions/secrets/{secret_name}', {
            owner: 'Zwiqler94',
            repo: 'jz-portfolio',
            secret_name: 'APP_CHECK_TOKEN',
            headers: {
                'X-GitHub-Api-Version': '2022-11-28'
            }
        });
        console.log(s);
    } catch (error) {
        core.setFailed(error.message);
    }
}

run();