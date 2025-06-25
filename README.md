# 🔧 Set up SSH Server Action

Set up an SSH server on GitHub Actions runners for remote debugging and file access across Windows,
macOS, and Linux.

**This is only part of the solution** - to actually connect to the SSH server, you'll need to expose it through:

- **Jump host** - Using a dedicated server as a proxy, see [SSH Command & Port Forwarding Action](https://github.com/marketplace/actions/ssh-command-port-forwarding)
- **Tailscale** - For secure network mesh connections, see [Tailscale Github Action](https://github.com/marketplace/actions/connect-tailscale)
- **ngrok** - For temporary public tunnels, see [Github Marketplace](https://github.com/marketplace?query=ngrok)
- [Other tunneling solutions](https://github.com/anderspitman/awesome-tunneling)

For a complete setup, see [lexbritvin/ssh-session-action](https://github.com/marketplace/actions/ssh-session).

## ✨ Features

- 🌐 **Cross-Platform Support** - Works seamlessly on Windows, macOS, and Linux runners
- 🔐 **Secure Authentication** - SSH key-based authentication with GitHub profile integration
- ⚙️ **Zero Configuration** - Works out of the box with sensible defaults
- 🎯 **Flexible Setup** - Customizable ports, users, and key management
- 🔑 **Auto Key Management** - Automatically fetch SSH keys from GitHub profiles
- 🧹 **Automatic Cleanup** - Clean teardown when workflow completes
- 📊 **Comprehensive Logging** - Detailed setup and connection information

## 🚀 Quick Start

### Basic Usage

```yaml
- name: Set up SSH Server
  uses: lexbritvin/ssh-server-action@v1
  with:
    authorized-keys: |
      ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB... user@example.com
      ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... another@example.com
    use-actor-ssh-keys: true

- name: Keep runner alive
  run: sleep 3600  # Keep alive for 1 hour
```

## 📋 Inputs

| Input                | Description                                    | Required | Default    |
|----------------------|------------------------------------------------|----------|------------|
| `port`               | SSH server port                                |          | `2222`     |
| `user`               | SSH username (use `:current` for current user) |          | `:current` |
| `authorized-keys`    | Authorized public keys (one per line)          |          | -          |
| `use-actor-ssh-keys` | Use workflow actor's GitHub SSH keys           |          | `false`    |

## 📤 Outputs

| Output      | Description          |
|-------------|----------------------|
| `hostname`  | SSH server hostname  |
| `port`      | SSH server port      |
| `username`  | SSH username         |
| `host-keys` | SSH host public keys |

## 🔒 Security Considerations

- **SSH Keys**: Always use SSH key authentication. Password authentication is disabled.
- **Firewall**: The action only opens the specified SSH port locally.
- **Cleanup**: SSH server is automatically stopped when the workflow ends.
- **Access Control**: Only specified authorized keys can connect.

### Best Practices

1. **Use Secrets**: Store SSH keys in repository secrets
2. **Limit Access**: Only add necessary SSH keys
3. **Monitor Usage**: Use time limits to prevent indefinite running
4. **Network Security**: SSH server only binds to localhost

```yaml
- name: Setup SSH with secrets
  uses: lexbritvin/ssh-server-action@v1
  with:
    authorized-keys: ${{ secrets.SSH_PUBLIC_KEYS }}
```

## 🌟 Platform Support

| Platform | Status | Notes                           |
|----------|--------|---------------------------------|
| Ubuntu   | ✅      | Full support with apt packages  |
| Windows  | ✅      | Uses Windows OpenSSH capability |
| macOS    | ✅      | Uses built-in SSH daemon        |

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**⭐ Star this repo if you find it useful!**

Made with ❤️ for the GitHub Actions community
