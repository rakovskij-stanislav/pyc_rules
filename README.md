# YARA Rules for PYC Magic

## Overview
This repository contains a collection of YARA rules designed to identify and classify Python compiled bytecode files (`*.pyc`) based on their magic numbers.

Magic numbers in Python bytecode files are used to indicate the version of Python with which the file was compiled.
This project helps in forensic analysis, malware detection, and reverse engineering tasks involving Python bytecode.

## Features

- **Version variety**: Rules for detecting different versions of Python from 1.5 to the latest alphas.
- **Actual state**: This repo regenerates new YARA ruleset each Sunday.

## Contributing

Contributions to this project are welcome! Here are some ways you can contribute:

- **Submit Bugs**: If you see some missed magics or inability to detect your pyc version - feel free to make an issue :)
- **Ideas**: Feel free to suggest features related to this project using Issues.
- **Stars**: Good option to support this project is to star this project. 
- Follow author at [Telegram](https://t.me/disasm_me_ch).

## License

This project is published under MIT license.