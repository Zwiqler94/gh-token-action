const core = require("@actions/core");
const github = require("@actions/github");

async function run() {
  try {
    const token = await core.getIDToken("public_repo");
    core.info(token);
    const octo = github.getOctokit({ token });
    const s = await octo.request(
      "GET /repos/{owner}/{repo}/actions/secrets/{secret_name}",
      {
        owner: "Zwiqler94",
        repo: "jz-portfolio",
        secret_name: "APP_ACCESS_TOKEN",
        headers: {
          "X-GitHub-Api-Version": "2022-11-28",
        },
      }
    );
    core.info(s);
  } catch (error) {
    core.setFailed(error.message);
  }
}

run();
