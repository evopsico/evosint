// Evosint launcher — starts the API server if needed, then opens the browser.
const { spawn, exec } = require('child_process');
const http = require('http');
const os = require('os');
const path = require('path');

const PORT = Number.parseInt(process.env.PORT, 10) || 3001;
const URL = `http://localhost:${PORT}`;

function checkServerRunning(port, pathName = '/health', timeoutMs = 2500) {
  return new Promise((resolve) => {
    const req = http.request({ hostname: '127.0.0.1', port, path: pathName, method: 'GET', timeout: timeoutMs }, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
    req.end();
  });
}

async function waitForServer(tries = 20) {
  for (let i = 0; i < tries; i++) {
    if (await checkServerRunning(PORT)) return true;
    await new Promise((r) => setTimeout(r, 750));
  }
  return false;
}

function startServerDetached() {
  const npmCmd = os.platform() === 'win32' ? 'npm.cmd' : 'npm';
  const child = spawn(npmCmd, ['start'], {
    cwd: __dirname, detached: true, stdio: 'ignore', shell: false,
    env: { ...process.env, PORT: String(PORT) },
  });
  child.unref();
  return child;
}

function openBrowser(url) {
  const plat = os.platform();
  if (plat === 'win32') exec(`start "" "${url}"`); // BUGFIX: start needs empty title arg or URL becomes the title
  else if (plat === 'darwin') exec(`open "${url}"`);
  else exec(`xdg-open "${url}"`);
}

async function launchApplication() {
  console.log('Evosint Launcher');
  console.log('==================');

  if (await checkServerRunning(PORT)) {
    console.log('Server is already running');
  } else {
    console.log('Starting OSINT server...');
    try { startServerDetached(); } catch (e) {
      console.error('Failed to start server:', e.message);
      console.log('Try running manually: npm start');
      process.exitCode = 1;
      return;
    }
    if (!await waitForServer()) {
      console.error('Server failed to start. Try: npm start');
      process.exitCode = 1;
      return;
    }
    console.log('Server started successfully');
  }

  console.log(`Opening ${URL} ...`);
  openBrowser(URL);
  console.log('Evosint launched in browser!');
  console.log('Usage: pick a tool card, enter a target, press Enter or Run.');
  console.log('Remember: authorized use only.');
}

process.on('SIGINT', () => { console.log('\nShutting down launcher...'); process.exit(0); });

launchApplication().catch((err) => { console.error('Launcher error:', err); process.exitCode = 1; });
