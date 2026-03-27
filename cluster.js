/**
 * PARAMANT WALL — cluster.js
 * Multi-core worker management voor productie schaal
 * Spawn 1 worker per CPU core (max 8)
 */
const cluster = require('cluster');
const os      = require('os');
const path    = require('path');

const WORKERS = Math.min(os.cpus().length, 8);

if (cluster.isPrimary) {
  console.log('[WALL CLUSTER] Primary PID', process.pid, '— spawning', WORKERS, 'workers');

  for (let i = 0; i < WORKERS; i++) cluster.fork();

  cluster.on('exit', function(worker, code, signal) {
    console.log('[WALL CLUSTER] Worker', worker.process.pid, 'died (code:', code, ') — restarting');
    setTimeout(function() { cluster.fork(); }, 1000); // 1s cooldown voor restart
  });

  // Graceful shutdown
  ['SIGTERM','SIGINT'].forEach(function(sig) {
    process.on(sig, function() {
      console.log('[WALL CLUSTER] Shutdown signal:', sig);
      Object.values(cluster.workers).forEach(function(w) { w.kill('SIGTERM'); });
      setTimeout(function() { process.exit(0); }, 5000);
    });
  });

  // Worker health monitoring
  setInterval(function() {
    const alive = Object.keys(cluster.workers).length;
    if (alive < WORKERS) {
      console.log('[WALL CLUSTER] Only', alive, '/', WORKERS, 'workers alive — spawning');
      for (let i = alive; i < WORKERS; i++) cluster.fork();
    }
  }, 30000);

} else {
  require('./wall-server.js');
}
