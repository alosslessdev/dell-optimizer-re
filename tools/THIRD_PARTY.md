# Third-party components and attribution

| Component | License | Use here |
|---|---|---|
| [lifenjoiner/ISx](https://github.com/lifenjoiner/ISx) | MIT | `tools/iss_stream_extract.py` is a Python re-implementation of ISx's InstallShield `ISSetupStream` format logic (key derivation, 1024-byte phase, block decode, zlib pass). |
| [ILSpy / ilspycmd](https://github.com/icsharpcode/ILSpy) | MIT | Used by `tools/decompile_all.sh` for reproduction; no decompiled output is distributed. |
| [Ghidra](https://ghidra-sre.org/) | Apache-2.0 | Used to analyze native binaries; no Ghidra output is distributed. |
| Linux kernel 7.2.9 | GPL-2.0 | `docs/07` quotes short excerpts (struct layouts, function fragments, constants) with file/line citations. |
| 7-Zip | LGPL-2.1+ (with unRAR restriction) | The reproduction pipeline may use a local 7-Zip binary; it is **not** redistributed here. |

## ISx MIT notice (required)

```
MIT License

Copyright (c) 2017 lifenjoiner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
