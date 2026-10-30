"""Build fixed author C++ ACORN with workspace-only pinned dependencies."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import shutil
import difflib
import tarfile

WORKSPACE = Path(__file__).resolve().parents[2]
OUT = WORKSPACE / "results" / "algorithm_ports_20261029" / "acorn_run01"
ROOT = WORKSPACE / ".runtime" / "algorithm_ports" / "acorn_toolchain"
BIN = ROOT / "unpacked" / "w64devkit" / "w64devkit" / "bin"
CMAKE = ROOT / "unpacked" / "cmake" / "cmake-3.31.12-windows-x86_64" / "bin" / "cmake.exe"
BLAS = ROOT / "unpacked" / "openblas"
BUILD = ROOT / "build"
RECEIPT = OUT / "build_receipt.json"


def main():
    parser=argparse.ArgumentParser();parser.add_argument("--attempt",type=int,default=1);args=parser.parse_args()
    sources=json.loads((OUT/"source_preparation.json").read_text(encoding="utf-8"))["source_roots"]
    state={"schema":"fixed_author_acorn_build_receipt_v1","attempt":args.attempt,"model_calls":0,"source_commit":"c259f11cdbec880671658eaa0d8747e2cc9de79d","steps":[],"algorithm_parameter_changes":False}
    path=OUT/f"build_attempt{args.attempt}.json"
    if path.exists():raise RuntimeError("attempt already recorded")
    def save():
        path.write_text(json.dumps(state,ensure_ascii=False,indent=2),encoding="utf-8")
        RECEIPT.write_text(json.dumps(state,ensure_ascii=False,indent=2),encoding="utf-8")
    env=os.environ.copy();env["PATH"]=str(BIN)+os.pathsep+str(BLAS/"bin")+os.pathsep+env.get("PATH","")
    env.update(OMP_NUM_THREADS="1",OPENBLAS_NUM_THREADS="1",MKL_NUM_THREADS="1")
    def run(name,command,timeout=600):
        start=time.time();log=OUT/f"build_attempt{args.attempt}_{name}.log"
        row={"name":name,"command":[str(x) for x in command],"log":str(log)};state["steps"].append(row);save()
        with log.open("wb") as stream:
            result=subprocess.run([str(x) for x in command],cwd=WORKSPACE,env=env,stdout=stream,stderr=subprocess.STDOUT,timeout=timeout)
        row.update(returncode=result.returncode,seconds=time.time()-start);save()
        print(json.dumps({"step":name,"returncode":result.returncode,"seconds":row["seconds"],"log":str(log)},ensure_ascii=True),flush=True)
        if result.returncode:raise RuntimeError(name+" failed; see preserved log")
    try:
        tree=json.loads((ROOT/"downloads"/"acorn-fixed-tree.json").read_text(encoding="utf-8"))
        allowed={"faiss/utils/AlignedTable.h","faiss/IndexACORN.h","faiss/impl/ACORN.cpp"}
        changed=[];patch=[]
        source=Path(sources["acorn"])
        with tarfile.open(ROOT/"downloads"/"acorn-c259f11.tar.gz","r:gz") as archive:
            for item in tree["tree"]:
                if item["type"]!="blob":continue
                current=(source/item["path"]).read_bytes()
                gitsha=hashlib.sha1(b"blob "+str(len(current)).encode()+b"\0"+current).hexdigest()
                if gitsha!=item["sha"]:
                    if item["path"] not in allowed:raise RuntimeError("unapproved author source change: "+item["path"])
                    original=archive.extractfile(source.name+"/"+item["path"]).read().decode("utf-8")
                    patch.extend(difflib.unified_diff(original.splitlines(True),current.decode("utf-8").splitlines(True),fromfile="a/"+item["path"],tofile="b/"+item["path"]))
                    changed.append({"path":item["path"],"original_git_blob":item["sha"],"current_sha256":hashlib.sha256(current).hexdigest()})
        (OUT/"compatibility.patch").write_text("".join(patch),encoding="utf-8")
        state["compatibility_files"]=changed
        state["other_author_tracked_blobs_match_fixed_commit"]=True
        save()
        common=["-G","Ninja",f"-DCMAKE_MAKE_PROGRAM={BIN/'ninja.exe'}",f"-DCMAKE_C_COMPILER={BIN/'gcc.exe'}",f"-DCMAKE_CXX_COMPILER={BIN/'g++.exe'}","-DCMAKE_BUILD_TYPE=Release"]
        run("configure_zlib",[CMAKE,"-S",sources["zlib"],"-B",BUILD/"zlib",*common,"-DBUILD_SHARED_LIBS=OFF"])
        run("build_zlib",[CMAKE,"--build",BUILD/"zlib","--target","zlibstatic","-j","4"])
        zlib=BUILD/"zlib"/"libzlibstatic.a"
        if not zlib.is_file():raise RuntimeError("expected workspace GNU zlibstatic library missing")
        gomp=BIN.parent/"lib"/"gcc"/"x86_64-w64-mingw32"/"16.2.0"/"libgomp.a"
        mingwthrd=BIN.parent/"lib"/"libmingwthrd.a"
        extra=[f"-DACORN_SOURCE_DIR={sources['acorn']}",f"-DNLOHMANN_SOURCE_DIR={sources['json']}","-DCMAKE_DISABLE_FIND_PACKAGE_MKL=TRUE",f"-DBLAS_LIBRARIES={BLAS/'lib'/'libopenblas.dll.a'}",f"-DLAPACK_LIBRARIES={BLAS/'lib'/'libopenblas.dll.a'}","-DBLA_VENDOR=OpenBLAS",f"-DZLIB_LIBRARY={zlib}",f"-DZLIB_INCLUDE_DIR={sources['zlib']}",f"-DOpenMP_gomp_LIBRARY={gomp}",f"-DOpenMP_mingwthrd_LIBRARY={mingwthrd}"]
        run("configure_acorn",[CMAKE,"-S",WORKSPACE/"experiments"/"algorithm_ports_20261029"/"acorn_cpp","-B",BUILD/"acorn",*common,*extra])
        run("build_acorn",[CMAKE,"--build",BUILD/"acorn","--target","acorn_port","-j","4"],1200)
        binary=BUILD/"acorn"/"acorn_port.exe"
        dll_source=BLAS/"bin"/"libopenblas.dll"
        dll_target=binary.parent/"libopenblas.dll"
        shutil.copyfile(dll_source,dll_target)
        state["adjacent_runtime_dll"]={"path":str(dll_target),"sha256":hashlib.sha256(dll_target.read_bytes()).hexdigest(),"copied_from_verified_asset":True}
        state.update(status="built_not_yet_algorithm_qualified",binary=str(binary),binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
        save()
    except Exception as error:
        state.update(status="build_failed_preserved",failure_type=type(error).__name__,failure_message=str(error));save();raise


if __name__=="__main__":main()
