# sshynergy

Run Synergy over SSH without setting up config files.

# Goals

- [x] Restart synergyc processes when screen sizes change (why I wrote this)
- [x] Generate synergy.conf given a list of hosts
- [x] Use ssh-agent
- [x] Parse `~/.ssh/config` to allow using shortnames
- [x] Respawn sessions if connections die
- [x] Respawn sessions when user chooses (hit `<Ctrl-L>`)
