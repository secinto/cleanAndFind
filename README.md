<h1 align="center">cleanAndFind</h1>
<h4 align="center">Tool for removing entries which are duplicates from subdomain enumeration, outlining the duplicates, 
and obtaining security settings</h4>
<p align="center">
  
  <img src="https://img.shields.io/github/watchers/secinto/cleanAndFind?label=Watchers&style=for-the-badge" alt="GitHub Watchers">
  <img src="https://img.shields.io/github/stars/secinto/cleanAndFind?style=for-the-badge" alt="GitHub Stars">
  <img src="https://img.shields.io/github/license/secinto/cleanAndFind?style=for-the-badge" alt="GitHub License">
</p>

Developed by Stefan Kraxberger (https://twitter.com/skraxberger/)  

Released as open source by secinto GmbH - https://secinto.com/  
Released under Apache License version 2.0 see LICENSE for more information

Description
----
cleanAndFind is a GO tool which removes duplicate subdomain entries from enumeration. Very often a lot of 
entries resolve to the same host and same information. Currently, our assumption is that these "useless" subdomains 
are added due to SEO optimization and don't provide any relevant information for penetration testing. It on the other
hand increases the amount of requests and time required for the recon phase. Thus, this tool removes these duplicates based
on the returned content.

# Installation Instructions

`cleanAndFind` requires **go1.20** to install successfully. Run the following command to get the repo:

```sh
git clone https://github.com/secinto/cleanAndFind.git
cd cleanAndFind
go build
go install
```

or the following to directly install it from the command line:

```sh
go install -v github.com/secinto/cleanAndFind/cmd/cleanAndFind@latest
```

# Usage

```sh
cleanAndFind -h
```

This will display help for the tool. Here are all the switches it supports.


```console
Usage:
  cleanAndFind [flags]

Flags:
INPUT:
   -p, -project string  project name for metadata addition

CONFIG:
   -config string  settings (Yaml) file location (default "$HOME/.config/cleanAndFind/settings.yaml")

DEBUG:
   -silent         show only results in output
   -version        show version of the project
   -v              show verbose output
   -nc, -no-color  disable colors in output

