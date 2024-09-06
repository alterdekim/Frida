# Frida

![GitHub last commit](https://img.shields.io/github/last-commit/alterdekim/Frida)
[![Jenkins Build](https://img.shields.io/jenkins/build?jobUrl=https%3A%2F%2Fjenkins.awain.net%2Fjob%2FFrida%2F)](https://jenkins.awain.net/job/Frida/)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/alterdekim/Frida)
![GitHub Repo stars](https://img.shields.io/github/stars/alterdekim/Frida)


A lightweight VPN software, focused on scalability, traffic obfuscation and simplicity.

## CLI Arguments

### Usage

```bash
./frida_vpn [FLAGS] [OPTIONS] <mode> --config <FILE>
```

### Options
| Name        | Value type           | Description  |
| ------------- |:-------------:| -----:|
| bind-address      | IP:PORT | The ip:port that would be used to bind server (config) |
| config      | FILE_PATH      |   The path to VPN configuration file |
| endpoint | IP:PORT      |    The ip:port that would be used by client to connect (config) |
| interface | NAME      |    Explicitly set network interface name for routing |
| internal-address | IP      |   The address of VPN server in it's subnet (config)  |
| keepalive | SECONDS_UINT      |   Keepalive packets interval (config) [default: 0]  |
| obfs-type | OBFS      |    Obfuscation protocol (config) [possible values: dns, veil, xor] |
| peer-cfg | FILE_PATH      |    The path to VPN peer configuration file |

### Flags
| Name (short)        | Name (long)           | Description  |
| ------------- |:-------------:| -----:|
|       | broadcast-mode | If set to true, then all incoming traffic with an unknown destination address will be forwarded to all peers (config) |
|       | grab-endpoint      |   If set to true, the endpoint address for peers will be grabbed from server config (config) |
| h | help      |    Prints help information |
| V | version      |    Prints version information |

### Args
| Name        | Required       | Description |
| ------------- |:-------------:| -----:|
| mode        | true           | Runs the program in certain mode [possible values: server, client, gen_cfg, new_peer] |

## Installation

On Linux, you can run this in a terminal (sudo required):

```
curl --proto '=https' --tlsv1.2 -sSf https://get-frida.awain.net | sh
```

Also you can download latest version from the jenkins.

## Android / IOS

There is an app for both Android and IOS devices.

### Android links
 - Google play: ...
 - Github: ...

### IOS links
 - Github: ...

## Todo
 - implement obfuscation protocols
 - make an Android build