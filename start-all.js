/**
 * SIEM Watchtower Unified Launcher
 * Starts Backend Server, ML Flask Service, React Client, and background Monitoring Agents.
 * Configures permissions and Python virtual environments automatically.
 */

const { spawn, execSync, exec } = require('child_process');
const path = require('path');
const fs = require('fs');

// Color constants for console output
const colors = {
  reset: '\x1b[0m',
  backend: '\x1b[32m[Backend]\x1b[0m',
  ml: '\x1b[34m[ML Service]\x1b[0m',
  frontend: '\x1b[35m[Frontend]\x1b[0m',
  system: '\x1b[36m[System]\x1b[0m',
  error: '\x1b[31m[System ERROR]\x1b[0m',
  success: '\x1b[32m[System SUCCESS]\x1b[0m'
};

const children = [];
const isWindows = process.platform === 'win32';

// Helper to log system messages
function logSys(msg) {
  console.log(`${colors.system} ${msg}`);
}

function logError(msg) {
  console.error(`${colors.error} ${msg}`);
}

function logSuccess(msg) {
  console.log(`${colors.success} ${msg}`);
}

// Line buffer stream redirector
function redirectOutput(stream, prefix) {
  if (!stream) return;
  let buffer = '';
  stream.on('data', (data) => {
    buffer += data.toString();
    const lines = buffer.split(/\r?\n/);
    buffer = lines.pop();
    for (const line of lines) {
      console.log(`${prefix} ${line}`);
    }
  });
  stream.on('end', () => {
    if (buffer) {
      console.log(`${prefix} ${buffer}`);
    }
  });
}

// Graceful exit handler
function cleanupAndExit() {
  logSys('Shutting down all active processes...');
  for (const child of children) {
    if (child && !child.killed) {
      try {
        if (isWindows) {
          // On Windows, tree kill is necessary to kill grandchild processes
          execSync(`taskkill /pid ${child.pid} /f /t`, { stdio: 'ignore' });
        } else {
          // Send SIGTERM to process group or individual process
          process.kill(-child.pid, 'SIGTERM');
        }
      } catch (err) {
        // Process might already be dead
        try {
          child.kill('SIGTERM');
        } catch (e) {}
      }
    }
  }
  logSys('Done. Goodbye!');
  process.exit(0);
}

// Register termination signals
process.on('SIGINT', cleanupAndExit);
process.on('SIGTERM', cleanupAndExit);
process.on('exit', () => {
  for (const child of children) {
    if (child && !child.killed) {
      try { child.kill('SIGKILL'); } catch (e) {}
    }
  }
});

// Main orchestrator function
async function main() {
  logSys('Starting SIEM Watchtower Unified Launcher...');

  // 1. Git index and filesystem permission synchronization
  try {
    const scriptsToPermit = [
      'start_all.bat',
      'restart_agents.bat',
      'fix_and_restart.bat',
      'ml_services/start_ml_service.bat',
      'agents/system_monitor/install_service.bat',
      'agents/system_monitor/install_task.ps1'
    ];

    // Set local file execute permissions if on Unix/Linux/macOS
    if (!isWindows) {
      logSys('Applying execute permissions to local scripts (Unix)...');
      for (const script of scriptsToPermit) {
        const fullPath = path.join(__dirname, script);
        if (fs.existsSync(fullPath)) {
          fs.chmodSync(fullPath, '755');
        }
      }
    }

    // Update Git index permissions so files retain execution bit when committed to GitHub
    try {
      execSync('git rev-parse --is-inside-work-tree', { stdio: 'ignore' });
      logSys('Git repository detected. Marking scripts as executable in Git tracking index...');
      for (const script of scriptsToPermit) {
        try {
          execSync(`git update-index --chmod=+x "${script}"`, { stdio: 'ignore' });
        } catch (err) {
          // File might not be staged/tracked yet, that's fine
        }
      }
      logSuccess('Git file permissions synchronized successfully.');
    } catch (gitErr) {
      logSys('Skipping Git index modification (not a git repo or git CLI missing).');
    }
  } catch (err) {
    logError(`Failed during permission configuration: ${err.message}`);
  }

  // 2. Install Node dependencies if missing
  const serverDir = path.join(__dirname, 'server');
  const clientDir = path.join(__dirname, 'client');

  if (!fs.existsSync(path.join(serverDir, 'node_modules'))) {
    logSys('Installing backend server dependencies...');
    execSync('npm install', { cwd: serverDir, stdio: 'inherit' });
  }

  if (!fs.existsSync(path.join(clientDir, 'node_modules'))) {
    logSys('Installing frontend client dependencies...');
    execSync('npm install', { cwd: clientDir, stdio: 'inherit' });
  }

  // 3. Database connection check
  logSys('Checking database connection...');
  try {
    execSync('node check_db.js', { cwd: serverDir, stdio: 'pipe' });
    logSuccess('Database is ONLINE.');
  } catch (dbErr) {
    logError('Database is OFFLINE or database credentials are incorrect.');
    logError('Please make sure PostgreSQL is running on port 5432 and configured correctly.');
    process.exit(1);
  }

  // 4. Set up Python ML Microservice Environment
  logSys('Configuring Python ML microservice environment...');
  let pythonCmd = 'python';
  try {
    execSync('python --version', { stdio: 'ignore' });
  } catch (pyErr) {
    try {
      execSync('python3 --version', { stdio: 'ignore' });
      pythonCmd = 'python3';
    } catch (py3Err) {
      logError('Python was not found. Please install Python 3.8+ and add it to your system PATH.');
      process.exit(1);
    }
  }

  const mlDir = path.join(__dirname, 'ml_services');
  const venvDir = path.join(mlDir, 'venv');
  const pythonExe = isWindows
    ? path.join(venvDir, 'Scripts', 'python.exe')
    : path.join(venvDir, 'bin', 'python');

  if (!fs.existsSync(venvDir)) {
    logSys('Creating Python virtual environment in ml_services/venv...');
    execSync(`"${pythonCmd}" -m venv venv`, { cwd: mlDir, stdio: 'inherit' });
  }

  logSys('Installing Python dependencies in virtual environment...');
  try {
    execSync(`"${pythonExe}" -m pip install -r requirements.txt --quiet`, { cwd: mlDir, stdio: 'inherit' });
  } catch (pipErr) {
    logSys('pip might be missing or broken. Attempting to bootstrap pip using ensurepip...');
    try {
      execSync(`"${pythonExe}" -m ensurepip`, { cwd: mlDir, stdio: 'inherit' });
      execSync(`"${pythonExe}" -m pip install -r requirements.txt --quiet`, { cwd: mlDir, stdio: 'inherit' });
    } catch (bootstrapErr) {
      logError(`Failed to install Python dependencies: ${bootstrapErr.message}`);
      process.exit(1);
    }
  }

  // Train ML models if missing
  const isoPkl = path.join(mlDir, 'isolation_forest.pkl');
  if (!fs.existsSync(isoPkl)) {
    logSys('Model files not found. Training isolation forest model now...');
    execSync(`"${pythonExe}" train.py`, { cwd: mlDir, stdio: 'inherit' });
    logSuccess('Model training complete.');
  } else {
    logSys('ML models already trained. Skipping training step.');
  }

  // 5. Start Background Agents (Windows only, system monitoring)
  if (isWindows) {
    logSys('Terminating old background monitoring agents...');
    try {
      execSync('taskkill /F /IM python.exe 2>nul', { stdio: 'ignore' });
      execSync('taskkill /F /IM pythonw.exe 2>nul', { stdio: 'ignore' });
    } catch (e) {}

    logSys('Clearing battery cache in database...');
    try {
      const clearScript = `
        const { Pool } = require('pg');
        const pool = new Pool({
            user: 'postgres',
            host: 'localhost',
            database: 'siem-watchtower',
            password: 'pava4484',
            port: 5432
        });
        async function clear() {
          try {
            await pool.query("DELETE FROM system_logs WHERE event_type IN ('BATTERY_STATUS', 'BATTERY_CRITICAL')");
            await pool.query("DELETE FROM system_logs WHERE event_type LIKE 'CHARGER_%'");
          } catch(e) {} finally { await pool.end(); }
        }
        clear();
      `;
      execSync(`node -e "${clearScript.replace(/\n/g, ' ')}"`, { cwd: serverDir, stdio: 'ignore' });
    } catch (e) {}

    logSys('Starting background monitoring agents...');
    try {
      const monitorDir = path.join(__dirname, 'agents', 'system_monitor');
      const agentScriptsDir = path.join(__dirname, 'agents', 'app_tracker');
      
      // Start system monitor
      exec('start /min "System Monitor Agent" pythonw main.py', { cwd: monitorDir });
      // Start app tracker
      exec('start /min "App Tracker Agent" pythonw app_tracker.py', { cwd: agentScriptsDir });
      logSuccess('Background agents launched.');
    } catch (agentErr) {
      logError(`Could not launch monitoring agents automatically: ${agentErr.message}`);
    }
  } else {
    logSys('Skipping Windows monitoring agents (unsupported platform).');
  }

  // 6. Concurrently spawn Server, ML microservice, and Frontend Client
  logSys('Starting components concurrently...');

  // Start Express server
  const backendProc = spawn('node', ['index.js'], {
    cwd: serverDir,
    detached: !isWindows, // Detach to allow process groups handling on Unix
    shell: true
  });
  children.push(backendProc);
  redirectOutput(backendProc.stdout, colors.backend);
  redirectOutput(backendProc.stderr, colors.backend);

  // Start ML Service Flask App
  const mlProc = spawn(pythonExe, ['app.py'], {
    cwd: mlDir,
    detached: !isWindows,
    shell: true
  });
  children.push(mlProc);
  redirectOutput(mlProc.stdout, colors.ml);
  redirectOutput(mlProc.stderr, colors.ml);

  // Start React Client
  const clientProc = spawn('npm', ['start'], {
    cwd: clientDir,
    detached: !isWindows,
    shell: true,
    env: { ...process.env, BROWSER: 'none' }
  });
  children.push(clientProc);
  redirectOutput(clientProc.stdout, colors.frontend);
  redirectOutput(clientProc.stderr, colors.frontend);

  logSuccess('All components initialized! Open dashboard at http://localhost:3000');
}

main().catch((err) => {
  logError(`Fatal orchestration error: ${err.message}`);
  cleanupAndExit();
});
