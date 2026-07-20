# Tailgate

[![Discord Invite][2]][1]

A minimal [Tailscale](https://github.com/tailscale/tailscale) client in C++.

## Overview

Tailgate is a Tailscale client written in portable C++. It aims to support platforms where Go is not
available.

## Platform Support

Tailgate currently supports:
- Linux
- UWP (Windows 10 RS2 or newer).
  - UWP clients require a Tailgate relay server.
  - This can be done by running `tailgate expose` on a Linux node.

Tailgate plans to support:
- [Wear OS](https://github.com/tailscale/tailscale/issues/3972).

## Features

1. Authentication
- Using [auth keys](https://tailscale.com/docs/features/access-control/auth-keys).
- Using QR codes.
2. Control
- Netmap
- DNS
- Exit Nodes
  - Specifying an exit node is supported, advertising is not.
- Presence
3. Data
- WireGuard direct
- DERP
- Ping
- Funnel
4. Interface
- CLI resembling the official `tailscale` client.

## Limitations

1. Security
- Tailgate does not support advanced security settings.
- Usage outside of trusted devices for personal Tailnets is not recommended.
2. Latency
- Random latency spikes sometimes occur.

## Components

1. `core`: Portable C++ core handling protocols and cryptography.
2. `cli`: Minimal command-line interface mimicking `tailscale`.
3. `linux`: Linux platform support.
4. `uwp`: UWP (Windows) platform support.

## Community

This repo is a part of [Project Reality][1].

Need help using this project? Join me on [Discord][1], and let's find a solution together.

[1]: https://reality.trungnt2910.com/discord
[2]: https://img.shields.io/discord/1185622479436251227?logo=discord&logoColor=white&label=Discord&labelColor=%235865F2
