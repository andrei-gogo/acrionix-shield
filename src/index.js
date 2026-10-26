const { runLeakScan } = require('./scanners/leak-scanner');
const { runSupplyChainScan } = require('./scanners/supply-chain-scanner');
const { runPythonScan } = require('./scanners/python-scanner');
const { runJavaScan } = require('./scanners/java-scanner');
const { runDotnetScan } = require('./scanners/dotnet-scanner');
const { runRubyScan } = require('./scanners/ruby-scanner');
const { runGoScan } = require('./scanners/go-scanner');
const { runPhpScan } = require('./scanners/php-scanner');
const { runDockerScan } = require('./scanners/docker-scanner');
const { runGitScan } = require('./scanners/git-scanner');
const { runActionsScan } = require('./scanners/actions-scanner');
const { formatResults } = require('./reporter');

module.exports = {
  runLeakScan,
  runSupplyChainScan,
  runPythonScan,
  runJavaScan,
  runDotnetScan,
  runRubyScan,
  runGoScan,
  runPhpScan,
  runDockerScan,
  runGitScan,
  runActionsScan,
  formatResults,
};
