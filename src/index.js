/**
 * GitHub Action: SSH Server Setup
 *
 * Sets up an SSH server on GitHub Actions runners across different platforms
 * (Windows, macOS, Linux) to enable remote debugging and file access.
 */

import * as core from "@actions/core";
import * as exec from "@actions/exec";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as https from "https";

// Configuration constants
const CONFIG = {
  DEFAULT_SSH_PORT: "2222",
  DEFAULT_USER_PLACEHOLDER: ":current",
  SSH_STARTUP_WAIT_MS: 2000,
  SSH_KEY_TYPES: ["rsa", "ecdsa", "ed25519"],
  GITHUB_KEYS_API_URL: "https://github.com",

  WINDOWS: {
    SSH_DIR: "C:\\ProgramData\\ssh",
    SFTP_SERVER: "C:\\Windows\\System32\\OpenSSH\\sftp-server.exe",
    AUTHORIZED_KEYS: "C:\\ProgramData\\ssh\\administrators_authorized_keys",
  },

  UNIX: {
    SSH_CONFIG_DIR: "/etc/ssh",
    SFTP_SERVER: "/usr/lib/openssh/sftp-server",
    PRIVILEGE_SEPARATION_DIR: "/run/sshd",
  },
};

// Platform detection
const platform = process.platform;
const isWindows = platform === "win32";
const isMacOS = platform === "darwin";
const isLinux = platform === "linux";

// Parse inputs
const sshPort = validatePort(core.getInput("port") || CONFIG.DEFAULT_SSH_PORT);
const sshUser = resolveUsername(core.getInput("user") || CONFIG.DEFAULT_USER_PLACEHOLDER);

/**
 * Main SSH server setup function
 */
async function setupSSHServer() {
  try {
    core.startGroup("🔧 SSH Server Setup");

    await logSystemInfo();
    await installSSHServer();
    await configureSSHServer();
    await setupAuthorizedKeys();
    await startSSHServer();
    await exportConnectionInfo();

    core.endGroup();
    core.info("✅ SSH server setup completed successfully");

  } catch (error) {
    core.endGroup();
    throw new Error(`SSH server setup failed: ${error.message}`);
  }
}

/**
 * Log system information for debugging
 */
async function logSystemInfo() {
  core.info("📊 System Information:");
  core.info(`  OS: ${platform}`);
  core.info(`  Architecture: ${process.arch}`);
  core.info(`  Node.js: ${process.version}`);
  core.info(`  Port: ${sshPort}`);
  core.info(`  User: ${sshUser}`);

  if (isLinux) {
    try {
      const distro = await getLinuxDistro();
      core.info(`  Distribution: ${distro.split("\n")[0]}`);
    } catch (error) {
      core.debug(`Could not determine Linux distribution: ${error.message}`);
    }
  }
}

/**
 * Install SSH server based on platform
 */
async function installSSHServer() {
  core.startGroup("📦 Installing SSH Server");

  try {
    if (isWindows) {
      await installWindowsSSH();
    } else if (isMacOS) {
      await installMacOSSSH();
    } else if (isLinux) {
      await installLinuxSSH();
    } else {
      throw new Error(`Unsupported platform: ${platform}`);
    }
  } catch (error) {
    core.endGroup();
    throw new Error(`SSH installation failed: ${error.message}`);
  }

  core.endGroup();
}

/**
 * Install OpenSSH on Windows
 */
async function installWindowsSSH() {
  core.info("🪟 Installing OpenSSH Server on Windows");

  try {
    // Check if already installed
    const checkResult = await exec.getExecOutput("powershell", [
      "Get-WindowsCapability -Online -Name OpenSSH.Server*",
    ], { ignoreReturnCode: true });

    if (checkResult.stdout.includes("State : Installed")) {
      core.info("OpenSSH Server is already installed");
      return;
    }

    core.info("Installing OpenSSH Server capability...");
    await exec.exec("powershell", [
      "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0",
    ]);

    core.info("Installing OpenSSH Client capability...");
    await exec.exec("powershell", [
      "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0",
    ]);

    core.info("✅ Windows SSH installation completed");

  } catch (error) {
    throw new Error(`Windows SSH installation failed: ${error.message}`);
  }
}

/**
 * Verify SSH availability on macOS
 */
async function installMacOSSSH() {
  core.info("🍎 Verifying SSH on macOS (built-in)");

  try {
    await exec.exec("which", ["sshd"]);
    core.info("✅ SSH daemon found");
  } catch (error) {
    throw new Error("SSH daemon not found on macOS");
  }
}

/**
 * Install OpenSSH on Linux
 */
async function installLinuxSSH() {
  core.info("🐧 Installing OpenSSH Server on Linux");

  try {
    // Check if sshd is already available
    try {
      await exec.exec("which", ["sshd"]);
      core.info("✅ SSH daemon is already installed");
      return;
    } catch (error) {
      core.info("SSH daemon not found, proceeding with installation...");
    }

    const distro = await getLinuxDistro();
    core.info(`Detected distribution: ${distro.split("\n")[0]}`);

    // Install based on distribution
    if (distro.includes("ubuntu") || distro.includes("debian")) {
      core.info("Installing on Debian/Ubuntu system...");
      await exec.exec("sudo", ["apt-get", "update", "-qq"]);
      await exec.exec("sudo", ["apt-get", "install", "-y", "openssh-server"]);
    } else if (distro.includes("centos") || distro.includes("rhel") || distro.includes("fedora")) {
      core.info("Installing on Red Hat/CentOS/Fedora system...");
      try {
        await exec.exec("sudo", ["dnf", "install", "-y", "openssh-server"]);
      } catch (error) {
        core.info("dnf not available, trying yum...");
        await exec.exec("sudo", ["yum", "install", "-y", "openssh-server"]);
      }
    } else if (distro.includes("alpine")) {
      core.info("Installing on Alpine system...");
      await exec.exec("sudo", ["apk", "add", "openssh-server"]);
    } else {
      core.warning("Unknown Linux distribution, attempting generic installation...");
      await exec.exec("sudo", ["apt-get", "update", "-qq"]);
      await exec.exec("sudo", ["apt-get", "install", "-y", "openssh-server"]);
    }

    core.info("✅ Linux SSH installation completed");

  } catch (error) {
    throw new Error(`Linux SSH installation failed: ${error.message}`);
  }
}

/**
 * Get Linux distribution information
 */
async function getLinuxDistro() {
  try {
    const output = await exec.getExecOutput("cat", ["/etc/os-release"]);
    return output.stdout.toLowerCase();
  } catch (error) {
    core.debug(`Could not read /etc/os-release: ${error.message}`);
    return "unknown";
  }
}

/**
 * Configure SSH server based on platform
 */
async function configureSSHServer() {
  core.startGroup("⚙️ Configuring SSH Server");

  try {
    const sshDir = getSSHDirectory();
    core.info(`SSH directory: ${sshDir}`);

    // Ensure SSH directory exists with proper permissions
    ensureDirectory(sshDir, 0o700);

    // Generate server keys
    await generateServerKeys();

    // Configure based on platform
    if (isWindows) {
      await configureWindowsSSH();
    } else {
      await configureUnixSSH(sshDir);
    }

    core.info("✅ SSH server configuration completed");

  } catch (error) {
    throw new Error(`SSH configuration failed: ${error.message}`);
  }

  core.endGroup();
}

/**
 * Configure SSH server on Windows
 */
async function configureWindowsSSH() {
  core.info("🪟 Configuring Windows SSH server");

  const sshDir = CONFIG.WINDOWS.SSH_DIR;
  const configPath = path.join(sshDir, "sshd_config");

  ensureDirectory(sshDir);

  const config = generateSSHDConfig("windows");
  fs.writeFileSync(configPath, config);

  core.info(`Configuration written to: ${configPath}`);
}

/**
 * Configure SSH server on Unix systems
 */
async function configureUnixSSH(sshDir) {
  core.info("🐧 Configuring Unix SSH server");

  const configPath = isLinux
    ? path.join(sshDir, "sshd_config_custom")
    : path.join(sshDir, "sshd_config");

  const config = generateSSHDConfig("unix");
  fs.writeFileSync(configPath, config);

  core.info(`Configuration written to: ${configPath}`);
}

/**
 * Generate SSH daemon configuration
 */
function generateSSHDConfig(platformType) {
  core.info(`📝 Generating SSH configuration for ${platformType}`);

  const isWindowsPlatform = platformType === "windows";
  const authorizedKeysPath = isWindowsPlatform
    ? CONFIG.WINDOWS.AUTHORIZED_KEYS
    : path.join(getSSHDirectory(), "authorized_keys");

  const sftpServerPath = isWindowsPlatform
    ? CONFIG.WINDOWS.SFTP_SERVER
    : CONFIG.UNIX.SFTP_SERVER;

  const windowsSpecificConfig = isWindowsPlatform ? `
# Windows-specific configuration
Match Group administrators
    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
` : "";

  return `
# GitHub Actions SSH Server Configuration
# Generated on: ${new Date().toISOString()}
# Platform: ${platformType}

# Basic settings
Port ${sshPort}
Protocol 2
ListenAddress 0.0.0.0

# Authentication
AuthorizedKeysFile "${authorizedKeysPath}"
AuthorizedKeysFile .ssh/authorized_keys
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM ${isWindowsPlatform ? "no" : "yes"}

# Security settings
PermitRootLogin no
MaxAuthTries 6
MaxSessions 10
LoginGraceTime 60

# Logging
SyslogFacility AUTH
LogLevel INFO

# Connection settings
ClientAliveInterval 60
ClientAliveCountMax 3
TCPKeepAlive yes

# Feature settings
X11Forwarding no
AllowTcpForwarding yes
GatewayPorts no
PermitTunnel no
PrintMotd no
PrintLastLog yes

# SFTP Subsystem
Subsystem sftp "${sftpServerPath}"

# User restrictions
AllowUsers ${sshUser}
${windowsSpecificConfig}
`.trim();
}

/**
 * Set up authorized SSH keys
 */
async function setupAuthorizedKeys() {
  core.startGroup("🔑 Setting up authorized keys");

  try {
    const publicKeys = core.getInput("authorized-keys");
    const useActorsKeys = core.getBooleanInput("use-actor-ssh-keys");
    const githubActor = process.env.GITHUB_ACTOR;

    let allKeys = [];

    // Add provided public keys
    if (publicKeys) {
      const keys = publicKeys.split("\n")
        .map(key => key.trim())
        .filter(key => key && !key.startsWith("#"));

      allKeys.push(...keys);
      core.info(`📋 Added ${keys.length} keys from input`);
    }

    // Fetch GitHub actor's SSH keys if requested
    if (useActorsKeys && githubActor) {
      core.info(`🔍 Fetching SSH keys for GitHub user: ${githubActor}`);

      try {
        const githubKeys = await fetchGitHubKeys(githubActor);
        allKeys.push(...githubKeys);
        core.info(`📋 Added ${githubKeys.length} keys from GitHub profile`);
      } catch (error) {
        core.warning(`Could not fetch GitHub keys: ${error.message}`);
      }
    }

    // Validate we have at least one key
    if (allKeys.length === 0) {
      throw new Error("No public keys provided. Please provide 'authorized-keys' input or enable 'use-actor-ssh-keys' and ensure you have SSH keys in your GitHub profile.");
    }

    // Write authorized keys file
    await writeAuthorizedKeys(allKeys);

    core.info(`✅ Configured ${allKeys.length} authorized keys`);

  } catch (error) {
    throw new Error(`Authorized keys setup failed: ${error.message}`);
  }

  core.endGroup();
}

/**
 * Write authorized keys to file with proper permissions
 */
async function writeAuthorizedKeys(keys) {
  const authorizedKeysPath = getAuthorizedKeysPath();
  const authorizedKeysContent = keys.join("\n") + "\n";

  core.info(`📝 Writing authorized keys to: ${authorizedKeysPath}`);

  // Ensure directory exists
  const dir = path.dirname(authorizedKeysPath);
  ensureDirectory(dir, 0o700);

  // Write the file
  fs.writeFileSync(authorizedKeysPath, authorizedKeysContent, { mode: 0o600 });

  // Set platform-specific permissions
  if (isWindows) {
    try {
      await exec.exec("powershell", [
        `icacls "${authorizedKeysPath}" /inheritance:r /remove "NT AUTHORITY\\Authenticated Users" /grant "SYSTEM:F" /grant "Administrators:F"`,
      ]);
      core.info("✅ Windows file permissions set");
    } catch (error) {
      core.warning(`Could not set Windows file permissions: ${error.message}`);
    }
  } else {
    // Set Unix permissions
    fs.chmodSync(dir, 0o700);
    fs.chmodSync(authorizedKeysPath, 0o600);
  }
}

/**
 * Fetch SSH keys from GitHub user profile
 */
async function fetchGitHubKeys(username) {
  const url = `${CONFIG.GITHUB_KEYS_API_URL}/${username}.keys`;

  core.info(`🌐 Fetching keys from: ${url}`);

  return new Promise((resolve, reject) => {
    const request = https.get(url, (res) => {
      let data = "";

      res.on("data", chunk => data += chunk);
      res.on("end", () => {
        if (res.statusCode === 200) {
          const keys = data.trim().split("\n").filter(key => key.trim());
          resolve(keys);
        } else {
          reject(new Error(`GitHub API returned status ${res.statusCode}`));
        }
      });
    });

    request.on("error", reject);
    request.setTimeout(10000, () => {
      request.destroy();
      reject(new Error("Request timeout"));
    });
  });
}

/**
 * Start SSH server based on platform
 */
async function startSSHServer() {
  core.startGroup("🚀 Starting SSH Server");

  try {
    if (isWindows) {
      await startWindowsSSH();
    } else if (isMacOS) {
      await startMacOSSSH();
    } else if (isLinux) {
      await startLinuxSSH();
    }

    // Wait for server to start
    core.info(`⏳ Waiting ${CONFIG.SSH_STARTUP_WAIT_MS}ms for SSH server to start...`);
    await new Promise(resolve => setTimeout(resolve, CONFIG.SSH_STARTUP_WAIT_MS));

    // Verify server is running
    await verifySSHServer();

    core.info("✅ SSH server started successfully");

  } catch (error) {
    throw new Error(`SSH server startup failed: ${error.message}`);
  }

  core.endGroup();
}

/**
 * Start SSH server on Windows
 */
async function startWindowsSSH() {
  core.info("🪟 Starting SSH server on Windows");

  try {
    // Enable and start SSH service
    await exec.exec("powershell", ["Set-Service -Name sshd -StartupType 'Automatic'"]);
    await exec.exec("powershell", ["Start-Service sshd"]);

    // Enable SSH firewall rule
    await exec.exec("powershell", [
      "New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22",
    ], { ignoreReturnCode: true });

  } catch (error) {
    throw new Error(`Windows SSH service startup failed: ${error.message}`);
  }
}

/**
 * Start SSH server on macOS
 */
async function startMacOSSSH() {
  core.info("🍎 Starting SSH server on macOS");

  const sshDir = getSSHDirectory();
  const configPath = path.join(sshDir, "sshd_config");

  try {
    await exec.exec("sudo", [
      "sh", "-c",
      `nohup /usr/sbin/sshd -f ${configPath} -p ${sshPort} -D > /tmp/sshd.log 2>&1 &`,
    ]);

  } catch (error) {
    throw new Error(`macOS SSH server startup failed: ${error.message}`);
  }
}

/**
 * Start SSH server on Linux
 */
async function startLinuxSSH() {
  core.info("🐧 Starting SSH server on Linux");

  const sshDir = getSSHDirectory();
  const configPath = path.join(sshDir, "sshd_config_custom");

  try {
    // Create privilege separation directory
    await exec.exec("sudo", ["mkdir", "-p", CONFIG.UNIX.PRIVILEGE_SEPARATION_DIR]);

    // Start sshd with custom configuration
    await exec.exec("sudo", [
      "sh", "-c",
      `nohup /usr/sbin/sshd -f ${configPath} -p ${sshPort} -D > /tmp/sshd.log 2>&1 &`,
    ]);

  } catch (error) {
    throw new Error(`Linux SSH server startup failed: ${error.message}`);
  }
}

/**
 * Verify SSH server is running and accessible
 */
async function verifySSHServer() {
  core.info("🔍 Verifying SSH server is running...");

  try {
    if (isWindows) {
      await exec.exec("powershell", [
        `Test-NetConnection -ComputerName localhost -Port ${sshPort} -InformationLevel Quiet`,
      ]);
    } else {
      // Try multiple verification methods
      try {
        await exec.exec("nc", ["-z", "localhost", sshPort]);
      } catch (error) {
        // Fallback to telnet if nc is not available
        await exec.exec("timeout", ["5", "telnet", "localhost", sshPort], { ignoreReturnCode: true });
      }
    }

    core.info(`✅ SSH server is running and accessible on port ${sshPort}`);

  } catch (error) {
    throw new Error(`SSH server verification failed: ${error.message}`);
  }
}

/**
 * Export connection information as outputs
 */
async function exportConnectionInfo() {
  core.startGroup("📤 Exporting connection information");

  try {
    const hostname = "localhost";

    // Set GitHub Actions outputs
    core.setOutput("hostname", hostname);
    core.setOutput("port", sshPort);
    core.setOutput("username", sshUser);

    // Export SSH host keys
    await exportHostKeys();

    // Log connection information
    core.info("🔗 SSH Connection Information:");
    core.info(`  📍 Host: ${hostname}`);
    core.info(`  🔌 Port: ${sshPort}`);
    core.info(`  👤 Username: ${sshUser}`);
    core.info(`  🔑 Connection: ssh ${sshUser}@${hostname} -p ${sshPort}`);

  } catch (error) {
    core.warning(`Failed to export connection information: ${error.message}`);
  }

  core.endGroup();
}

/**
 * Export SSH host keys to GitHub Actions outputs
 */
async function exportHostKeys() {
  try {
    const keys = await getServerPublicKeys();

    if (keys.length === 0) {
      core.warning("⚠️ No server public keys found to export");
      core.setOutput("host-keys", "");
      return;
    }

    // Combine all keys into a single string
    const allKeys = keys.map(key => key.content.trim()).join("\n");
    core.setOutput("host-keys", allKeys);

    core.info(`🔑 Exported ${keys.length} SSH host keys`);

    // Log key fingerprints for verification
    for (const key of keys) {
      core.info(`  🔐 ${key.type.toUpperCase()}: ${key.content.split(" ")[1].substring(0, 20)}...`);
    }

  } catch (error) {
    core.warning(`Failed to export SSH host keys: ${error.message}`);
    core.setOutput("host-keys", "");
  }
}

/**
 * Get SSH server public keys
 */
async function getServerPublicKeys() {
  const sshDir = isWindows ? CONFIG.WINDOWS.SSH_DIR : CONFIG.UNIX.SSH_CONFIG_DIR;
  const keys = [];

  for (const type of CONFIG.SSH_KEY_TYPES) {
    const keyPath = path.join(sshDir, `ssh_host_${type}_key.pub`);

    if (fs.existsSync(keyPath)) {
      try {
        const content = fs.readFileSync(keyPath, "utf8");
        keys.push({ type, content });
      } catch (error) {
        core.debug(`Could not read ${type} key: ${error.message}`);
      }
    }
  }

  return keys;
}

/**
 * Generate SSH server keys
 */
async function generateServerKeys() {
  core.info("🔐 Generating SSH server keys");

  try {
    if (isWindows) {
      // On Windows, server keys are generated automatically by the service
      core.info("Windows will generate server keys automatically");
    } else {
      // Generate all standard server keys on Unix systems
      await exec.exec("sudo", ["ssh-keygen", "-A"]);
    }

    core.info("✅ Server keys generated successfully");

  } catch (error) {
    throw new Error(`Server key generation failed: ${error.message}`);
  }
}

/**
 * Cleanup SSH server and resources
 */
async function cleanupSSHServer() {
  core.startGroup("🧹 Cleaning up SSH server");

  try {
    core.info("Stopping SSH server...");

    if (isWindows) {
      await exec.exec("powershell", ["Stop-Service sshd -Force"], { ignoreReturnCode: true });
    } else {
      // Kill SSH processes running on the custom port
      await exec.exec("sudo", ["pkill", "-f", `sshd.*-p ${sshPort}`], { ignoreReturnCode: true });
    }

    core.info("✅ SSH server cleanup completed");

  } catch (error) {
    core.warning(`SSH cleanup failed: ${error.message}`);
  }

  core.endGroup();
}

// Utility functions

/**
 * Get SSH directory path based on platform
 */
function getSSHDirectory() {
  if (isWindows) {
    return CONFIG.WINDOWS.SSH_DIR;
  }
  return path.join(os.homedir(), ".ssh");
}

/**
 * Get authorized keys file path based on platform
 */
function getAuthorizedKeysPath() {
  if (isWindows) {
    return CONFIG.WINDOWS.AUTHORIZED_KEYS;
  }
  return path.join(getSSHDirectory(), "authorized_keys");
}

/**
 * Ensure directory exists with proper permissions
 */
function ensureDirectory(dirPath, mode = 0o755) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true, mode });
    core.info(`📁 Created directory: ${dirPath}`);
  }
}

/**
 * Validate SSH port number
 */
function validatePort(port) {
  const portNum = parseInt(port, 10);
  if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
    throw new Error(`Invalid port number: ${port}`);
  }
  return port;
}

/**
 * Resolve username from input
 */
function resolveUsername(userInput) {
  if (userInput === CONFIG.DEFAULT_USER_PLACEHOLDER) {
    return os.userInfo().username;
  }
  return userInput;
}

/**
 * Main execution logic
 */
async function main() {
  const isPost = !!core.getState("isPost");

  try {
    if (!isPost) {
      // Setup phase
      core.saveState("isPost", "true");
      await setupSSHServer();
    } else {
      // Cleanup phase
      await cleanupSSHServer();
    }
  } catch (error) {
    core.setFailed(`❌ Action failed: ${error.message}`);
    process.exit(1);
  }
}

// Execute main function
main().catch(error => {
  core.setFailed(`💥 Unexpected error: ${error.message}`);
  process.exit(1);
});
