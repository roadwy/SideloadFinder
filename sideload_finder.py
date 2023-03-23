#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# https://github.com/geemion

import frida
import subprocess
from win32process import CREATE_SUSPENDED
import psutil
import os
import argparse

exe_name = ""
out_name = ""


def on_message(message, data):
    flag = message["payload"]["Flag"]
    LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020
    if flag & LOAD_LIBRARY_AS_IMAGE_RESOURCE:
        return
    msg = "{},{},0x{:x}\n".format(exe_name, message["payload"]["DllName"], message["payload"]["Flag"])
    print(msg)
    if len(out_name) == 0:
        return
    with open(out_name, "a+") as f:
        f.write(msg)


def create_process(exe_path):
    global exe_name 
    exe_name = exe_path
    try:
        process = subprocess.Popen(exe_path, creationflags=CREATE_SUSPENDED)
        return process.pid
    except Exception as e:
        return None


def frida_hook(pid, timeout=3):
    session = frida.attach(pid)
    script = session.create_script("""
var LoadLibraryEx = Module.findExportByName("api-ms-win-core-libraryloader-l1-2-0.dll", "LoadLibraryExW");
if (LoadLibraryEx == 0) {
    LoadLibraryEx = Module.findExportByName("kernelbase.dll", "LoadLibraryExW");
}
Interceptor.attach(LoadLibraryEx, {
    onEnter: function(args, state) {
        this.lpLibFileName = Memory.readUtf16String(args[0]);
        this.dwFlags = args[2].toUInt32();
    },
    onLeave: function(retval, state) {
        if (retval == 0) {
            if (this.dwFlags != 2) {
                send({"DllName":this.lpLibFileName, "Flag":this.dwFlags})
            }
        }
    }
});
    """)
    script.on('message', on_message)
    script.load()
    p = psutil.Process(pid)
    p.resume()
    try:
        p.wait(timeout=timeout)
    except Exception as e:
        p.kill()
    session.detach()


def get_sample_files(dir_path):
    exe_file = set()
    for parent, _, filenames in os.walk(dir_path):
        for filename in filenames:
            if filename.lower().endswith(".exe") == False:
                continue
            file_path = os.path.join(parent, filename)
            exe_file.add(file_path)
    return exe_file


def find_sideload(samples_dir):
    exes = get_sample_files(samples_dir)
    for exe in exes:
        pid = create_process(exe)
        if pid is not None:
            frida_hook(pid)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Windows sideload finder by frida')
    parser.add_argument('-i', type=str, help='exe samples dir')
    parser.add_argument('-o', type=str, help='output csv path')
    args = parser.parse_args()
    if not args.i or not args.o:
        parser.print_help()
        exit(1)
    out_name = args.o
    find_sideload(args.i)

