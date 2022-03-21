# pwncat_dirtypipe
[![asciicast](https://asciinema.org/a/UGXf1HIBdOU7Hrl4an8dO6HXJ.svg)](https://asciinema.org/a/UGXf1HIBdOU7Hrl4an8dO6HXJ)
pwncat module that automatically exploits CVE-2022-0847 (dirtypipe)
## Introduction
The purpose of this module is to attempt to exploit CVE-2022-0847 (dirtypipe) on a target when using pwncat.

There is no need to setup any directories, compile any source or even have gcc on the remote target; the dirtypipe module takes care of this automatically using the pwncat framework.

## Setup and Use
- Simply copy `dirtypipe.py` somewhere on your host where pwncat-cs is installed. ie: /home/user/pwncat_mods
- In pwncat, simply type: `load /home/user/pwncat_mods`
- To confirm the module loaded, type: `search dirtypipe`. You should see something like this:
```
(local) pwncat$ search dirtypipe
                                                      Results                                                      
                   ╷                                                                                               
  Name             │ Description                                                                                   
 ══════════════════╪══════════════════════════════════════════════════════════════════════════════════════════════ 
  dirtypipe        │ Exploit CVE-2022-0847 to local privesc to root via dirtypipe
``` 
- To execute, simply type `run dirtypipe`. If it's successful, you should see the UID change to 0, and now be root. ie:
```
(local) pwncat$ run dirtypipe

```

## Tips
- If you don't want to always call `load`, you can have pwncat automatically load this module on startup by placing it in `~/.local/share/pwncat/modules`
- To use the cross-compiler to build the exploit on your machine and upload it to the target, you need to set the **cross** variable in your pwncatrc file. This file is typically found at ~/.local/share/pwncat/pwncatrc`. ie:
```
# Set the gcc path
set cross "/usr/bin/gcc"
```

## Thanks
A special shout out to [Caleb Stewart](https://github.com/calebstewart/pwncat) for having an awesome framework to build this on top of.  
