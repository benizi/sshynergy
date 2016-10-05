# sshynergy

Run Synergy over SSH without setting up config files.

## Status

It works, kinda.  Finished my [initial goals](#initial-goals), but the code is
horrible (see: [Goals](#goals)).

## Quirks

Default setup is to use the current host and a host called `_`.

- Set it up via `~/.ssh/config` (this shells out to `ssh` to parse it)
- Should point to your current machine's "default" neighbor.

## Initial Goals

- [x] Restart synergyc processes when screen sizes change (why I wrote this)
- [x] Generate synergy.conf given a list of hosts
- [x] Use ssh-agent
- [x] Parse `~/.ssh/config` to allow using shortnames
- [x] Respawn sessions if connections die
- [x] Respawn sessions when user chooses (hit `<Ctrl-L>`)

## Goals

- [ ] Make it `go get`-able
- [ ] Better code (basically hacked together over a couple evenings)
    - [ ] Clearly I don't understand or am misusing channels
    - [ ] Better handling of restarting/orphaning processes (probably related)
- [ ] Move OpenSSH config parsing (by invoking `ssh -G`) to a library
