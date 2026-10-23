# Central network passwords

The web console accepts a custom password when creating a network or editing
its settings. Surrounding whitespace is trimmed from an explicitly entered
password. Saving unrelated settings preserves the existing password exactly,
including legacy passwords that contain surrounding whitespace. A password
changed by another session is retained when the local password field is unchanged.

Leaving the creation field empty generates a password automatically. Selecting
**No password** creates an empty shared password instead. No-password networks
can also enable **Secure Mode** and issue credentials to temporary members.

Permanent members use the shared network identity, even when its password is
empty. Temporary members use their own credential identity and receive no shared
password. When an empty shared password and Secure Mode are both enabled, the
generated TOML records the identity explicitly:

```toml
[network_identity]
network_name = "example-network"
network_secret = ""
authentication = "shared_secret"

[secure_mode]
enabled = true
```

The marker preserves the member's identity when the configuration is reloaded.
Existing credential configurations without this marker keep their previous
meaning: an omitted or empty password with Secure Mode identifies a credential
member. Nodes must run a version that understands the marker to reload a
passwordless Secure Mode network correctly; older versions ignore it.
