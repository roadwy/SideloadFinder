#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# https://github.com/geemion
import json
import frida
import subprocess
from win32process import CREATE_SUSPENDED
import psutil
import os
import sys
import pefile
import argparse


class SideLoadFinder:
    def __init__(self, out_path, timeout):
        self.out_path = out_path
        self.timeout = timeout
        self.LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020
        self.image_path = ""
        self.line_content = ""
        self.frida_script = """
var LoadLibraryEx = Module.findExportByName("api-ms-win-core-libraryloader-l1-2-0.dll", "LoadLibraryExW");
if (LoadLibraryEx == 0) {
    LoadLibraryEx = Module.findExportByName("kernelbase.dll", "LoadLibraryExW");
}
var FakeModule = 0x777777;
Interceptor.attach(LoadLibraryEx, {
    onEnter: function(args, state) {
        this.lpLibFileName = Memory.readUtf16String(args[0]);
        this.dwFlags = args[2].toUInt32();
    },
    onLeave: function(retval, state) {
        if (retval == 0) {
            if (this.dwFlags != 2) {
                send({"payload_type":"dll", "dll":this.lpLibFileName, "flag":this.dwFlags, "type": "dynamic"});
                retval.replace(FakeModule);
            }
        }
    }
});
var GetProcAddress = Module.findExportByName("kernel32.dll", "GetProcAddress");
Interceptor.attach(GetProcAddress, {
    onEnter: function(args, state) {
        this.Procname = Memory.readAnsiString(args[1]);
        this.module = args[0];
        if(this.module == FakeModule){
        send({"payload_type":"proc", "proc":this.Procname});
        }
    },
});
"""

    def on_message(self, message, data):
        if message["type"] == "send":
            print(message)
            if message["payload"]["payload_type"] == "dll":
                self.handle_dll_msg(message)
            else:
                self.handle_proc_msg(message)
        else:
            print(message)

    def handle_dll_msg(self, message):
        self.out_csv()
        flag = message["payload"]["flag"]
        if flag & self.LOAD_LIBRARY_AS_IMAGE_RESOURCE:
            return
        self.line_content = "{},{},{},0x{:x}".format(message["payload"]["type"], self.image_path, message["payload"]["dll"], flag)

    def handle_proc_msg(self, message):
        proc = message["payload"]["proc"]
        self.line_content = "{},{}".format(self.line_content, proc)

    def out_csv(self):
        if self.line_content == "":
            return
        self.line_content = self.line_content + "\n"
        with open(self.out_path, "a+") as f:
            f.write(self.line_content)
            print(self.line_content)
            self.line_content = ""

    def dynamic_finder(self, image_path):
        try:
            self.image_path = image_path
            pid = subprocess.Popen(self.image_path, creationflags=CREATE_SUSPENDED).pid
            session = frida.attach(pid)
            script = session.create_script(self.frida_script)
            script.on('message', self.on_message)
            script.load()
            p = psutil.Process(pid)
            p.resume()
            try:
                p.wait(timeout=self.timeout)
            except Exception as e:
                print(e)
                p.kill()
            session.detach()
        except Exception as e:
            print(e)
        finally:
            self.out_csv()

    def is_dll_exist(self, image_path, dll_name):
        cur_dir = os.path.dirname(image_path)
        windir = os.getenv("windir")
        sys32dir = os.path.join(windir, "system32")
        path_dirs = os.getenv("PATH")
        search_dirs = path_dirs.split(";")
        search_dirs.extend([cur_dir, windir, sys32dir])
        for dir in search_dirs:
            dll_path = os.path.join(dir, dll_name)
            if os.path.exists(dll_path):
                return True
        return False

    def static_finder(self, image_path):
        try:
            self.image_path = image_path
            pe = pefile.PE(image_path)
            for dll in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = str(dll.dll, encoding='ansi')
                if not self.is_dll_exist(image_path, dll_name):
                    msg = '{"type": "send", "payload": {"payload_type": "dll", "dll":"'+ dll_name + '", "flag": 0, "type":"static"}}'
                    self.on_message(json.loads(msg), "")
                    print(dll_name)
        except Exception as e:
            print(e)
        finally:
            self.out_csv()
    
    def finder(self, image_path):
        self.static_finder(image_path)
        self.dynamic_finder(image_path)

    def run(self, image_dir):
        for parent, _, filenames in os.walk(image_dir):
            for filename in filenames:
                if not filename.lower().endswith(".exe"):
                    continue
                image_path = os.path.join(parent, filename)
                self.finder(image_path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Windows sideload finder by frida')
    parser.add_argument('-i', type=str, help='exe samples dir')
    parser.add_argument('-o', type=str, help='output csv path')
    args = parser.parse_args()
    if not args.i or not args.o:
        parser.print_help()
        sys.exit()
    out_path = args.o
    image_dir = args.i
    finder = SideLoadFinder(out_path, 2)
    finder.run(image_dir)

