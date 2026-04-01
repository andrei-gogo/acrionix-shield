const { runLeakScan } = require('./scanners/leak-scanner');
const { runSupplyChainScan } = require('./scanners/supply-chain-scanner');
const { runPythonScan } = require('./scanners/python-scanner');
const { runDockerScan } = require('./scanners/docker-scanner');
const { runGitScan } = require('./scanners/git-scanner');
const { formatResults } = require('./reporter');

module.exports = {
  runLeakScan,
  runSupplyChainScan,
  runPythonScan,
  runDockerScan,
  runGitScan,
  formatResults,
};
